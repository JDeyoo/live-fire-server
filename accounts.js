// Live Fire accounts: a username and password, and the progress that goes with them.
// Passwords are never stored: only a salted scrypt hash. Logging in hands back a random token; the game keeps the token
// and the server keeps only its SHA-256, so a stolen database can't be used to log in.
// Storage: Postgres when DATABASE_URL is set (a free Neon database works), otherwise a JSON file for local testing.
'use strict';
const crypto = require('crypto');
const fs = require('fs');

const NAME_RE = /^[A-Za-z0-9_]{3,16}$/;
const MAX_DATA = 64 * 1024;                  // progress is a few KB; this is a ceiling, not a target
const TRIES_PER_MIN = 12;                    // login / sign-up attempts per address per minute

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const scrypt = (pass, salt) => new Promise((ok, no) => crypto.scrypt(pass, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => e ? no(e) : ok(k)));

// ---------------- storage ----------------
function fileStore(file) {
  let db = { users: {}, tokens: {} }; try { db = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { }
  const save = () => fs.writeFileSync(file, JSON.stringify(db));
  return {
    kind: 'file',
    async ready() { },
    async getUser(key) { return db.users[key] || null; },
    async addUser(u) { if (db.users[u.key]) return false; db.users[u.key] = u; save(); return true; },
    async setData(key, data) { if (db.users[key]) { db.users[key].data = data; db.users[key].updated = Date.now(); save(); } },
    async addToken(h, key) { db.tokens[h] = { key, at: Date.now() }; save(); },
    async userByToken(h) { const t = db.tokens[h]; return t ? db.users[t.key] || null : null; },
    async dropToken(h) { delete db.tokens[h]; save(); },
  };
}
function pgStore(url) {
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: url, ssl: /localhost|127\.0\.0\.1/.test(url) ? false : { rejectUnauthorized: false }, max: 4 });
  const q = (sql, args) => pool.query(sql, args);
  const row = r => r && { key: r.key, name: r.name, salt: r.salt, hash: r.hash, data: r.data, created: +r.created, updated: +r.updated };
  return {
    kind: 'postgres',
    async ready() {
      await q(`create table if not exists lf_users (key text primary key, name text not null, salt text not null, hash text not null, data jsonb, created bigint not null, updated bigint not null)`);
      await q(`create table if not exists lf_tokens (hash text primary key, key text not null references lf_users(key) on delete cascade, at bigint not null)`);
    },
    async getUser(key) { return row((await q('select * from lf_users where key = $1', [key])).rows[0]); },
    async addUser(u) { const r = await q('insert into lf_users (key, name, salt, hash, data, created, updated) values ($1,$2,$3,$4,$5,$6,$6) on conflict (key) do nothing', [u.key, u.name, u.salt, u.hash, u.data, u.created]); return r.rowCount === 1; },
    async setData(key, data) { await q('update lf_users set data = $2, updated = $3 where key = $1', [key, data, Date.now()]); },
    async addToken(h, key) { await q('insert into lf_tokens (hash, key, at) values ($1,$2,$3)', [h, key, Date.now()]); },
    async userByToken(h) { return row((await q('select u.* from lf_tokens t join lf_users u on u.key = t.key where t.hash = $1', [h])).rows[0]); },
    async dropToken(h) { await q('delete from lf_tokens where hash = $1', [h]); },
  };
}
let store = null, storeErr = null;
try { store = process.env.DATABASE_URL ? pgStore(process.env.DATABASE_URL) : process.env.ACCOUNTS_FILE ? fileStore(process.env.ACCOUNTS_FILE) : null; }
catch (e) { storeErr = e.message; console.error('accounts: storage failed to start:', e.message); }
const ready = store ? store.ready().then(() => true, e => { storeErr = e.message; console.error('accounts: storage not ready:', e.message); return false; }) : Promise.resolve(false);

// ---------------- the API ----------------
const tries = new Map();   // address -> [count, window start]
function limited(ip) { const now = Date.now(), t = tries.get(ip); if (!t || now - t[1] > 60000) { tries.set(ip, [1, now]); return false; } return ++t[0] > TRIES_PER_MIN; }
setInterval(() => { const now = Date.now(); for (const [k, t] of tries) if (now - t[1] > 60000) tries.delete(k); }, 60000).unref();

function cleanData(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return null;
  const text = JSON.stringify(d); return text.length > MAX_DATA ? null : JSON.parse(text);
}
async function newToken(key) { const tok = crypto.randomBytes(32).toString('base64url'); await store.addToken(sha(tok), key); return tok; }

const routes = {
  async register(b) {
    const name = String(b.name || ''), pass = String(b.pass || '');
    if (!NAME_RE.test(name)) return [400, { error: 'Usernames are 3 to 16 letters, numbers or _' }];
    if (pass.length < 6 || pass.length > 72) return [400, { error: 'Passwords need at least 6 characters' }];
    const key = name.toLowerCase(), salt = crypto.randomBytes(16).toString('hex'), hash = (await scrypt(pass, salt)).toString('hex'), data = cleanData(b.data) || {};
    if (!await store.addUser({ key, name, salt, hash, data, created: Date.now() })) return [409, { error: 'That username is taken' }];
    return [200, { name, token: await newToken(key), data }];
  },
  async login(b) {
    const name = String(b.name || ''), pass = String(b.pass || ''), u = NAME_RE.test(name) ? await store.getUser(name.toLowerCase()) : null;
    const hash = await scrypt(pass, u ? u.salt : 'no-such-user');   // same work either way, so timing doesn't say which names exist
    if (!u || !crypto.timingSafeEqual(hash, Buffer.from(u.hash, 'hex'))) return [401, { error: 'Wrong username or password' }];
    return [200, { name: u.name, token: await newToken(u.key), data: u.data || {} }];
  },
  async me(b, tok) { const u = tok && await store.userByToken(sha(tok)); return u ? [200, { name: u.name, data: u.data || {} }] : [401, { error: 'Signed out' }]; },
  async save(b, tok) {
    const u = tok && await store.userByToken(sha(tok)); if (!u) return [401, { error: 'Signed out' }];
    const data = cleanData(b.data); if (!data) return [400, { error: 'Progress too big' }];
    await store.setData(u.key, data); return [200, { ok: true }];
  },
  async logout(b, tok) { if (tok) await store.dropToken(sha(tok)); return [200, { ok: true }]; },
};

// returns true if it handled the request
function handle(req, res) {
  if (!req.url.startsWith('/api/')) return false;
  const head = { 'content-type': 'application/json', 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type, authorization', 'access-control-allow-methods': 'POST, GET, OPTIONS' };
  const reply = (code, obj) => { res.writeHead(code, head); res.end(JSON.stringify(obj)); };
  if (req.method === 'OPTIONS') { res.writeHead(204, head); res.end(); return true; }
  const what = req.url.slice(5).split('?')[0];
  if (what === 'status') { ready.then(ok => reply(200, { accounts: ok ? store.kind : 'off', error: ok ? undefined : storeErr ? 'storage error' : 'no database set' })); return true; }
  const fn = routes[what]; if (!fn || req.method !== 'POST') { reply(404, { error: 'Not found' }); return true; }
  let body = '', big = false;
  req.on('data', c => { body += c; if (body.length > MAX_DATA + 4096) { big = true; req.destroy(); } });
  req.on('end', async () => {
    if (big) return;
    if (!await ready) return reply(503, { error: 'Accounts are offline right now' });
    const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if ((what === 'login' || what === 'register') && limited(ip)) return reply(429, { error: 'Too many tries. Wait a minute' });
    let b; try { b = JSON.parse(body || '{}'); } catch (e) { return reply(400, { error: 'Bad request' }); }
    const tok = String(req.headers.authorization || '').replace(/^Bearer /, '');
    try { const [code, obj] = await fn(b, tok); reply(code, obj); } catch (e) { console.error('accounts:', what, e.message); reply(500, { error: 'Server error, try again' }); }
  });
  return true;
}
module.exports = { handle };
