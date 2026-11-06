// Live Fire public lobby server.
// One lobby per mode (Zombies by default, ?room=ffa for Free For All): it hands out the map seed, relays what each player does, and remembers
// the parts of the world that changed (walls blown up, sandbags moved) so late joiners see the same map.
// The oldest player in the lobby is the "host": their game runs the enemies and the wave clock,
// and the server passes the enemy snapshots on to everyone else. No dependencies: plain Node.
'use strict';
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const MAX_PLAYERS = 16;
const MAX_MSG = 200 * 1024;            // biggest message we accept (an enemy snapshot is a few KB)
const MSGS_PER_SEC = 90;               // per player; anything beyond that is dropped

const FFA_TARGET = 20;                 // eliminations to win a Free For All round
const FFA_BREAK = 8000;                // ms between the win and the next map

// id -> { sock, name, joined, bucket, last } per room, each with its own host and world
function freshLobby() { return { seed: Math.floor(Math.random() * 1e9), wave: null, walls: new Set(), props: {}, scores: {}, ended: false }; }
function makeRoom(name) { return { name, players: new Map(), host: null, hostSeen: 0, lobby: freshLobby() }; }
const rooms = { zombies: makeRoom('zombies'), ffa: makeRoom('ffa') };
let nextId = 1;

// ---------------- the tiny WebSocket layer (RFC 6455, text frames only) ----------------
function frame(text) {
  const data = Buffer.from(text), n = data.length;
  const head = n < 126 ? Buffer.from([0x81, n]) : n < 65536 ? Buffer.from([0x81, 126, n >> 8, n & 255]) : (() => { const h = Buffer.alloc(10); h[0] = 0x81; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); return h; })();
  return Buffer.concat([head, data]);
}
function send(p, obj) { if (p && !p.sock.destroyed) p.sock.write(typeof obj === 'string' ? frame(obj) : frame(JSON.stringify(obj))); }
function broadcast(room, obj, except) { const f = frame(typeof obj === 'string' ? obj : JSON.stringify(obj)); for (const [id, p] of room.players) if (id !== except && !p.sock.destroyed) p.sock.write(f); }

function accept(req, sock) {
  const key = req.headers['sec-websocket-key'];
  const room = rooms[new URL(req.url, 'http://x').searchParams.get('room')] || rooms.zombies;
  if (!key || room.players.size >= MAX_PLAYERS) { sock.end('HTTP/1.1 503 Lobby full\r\n\r\n'); return; }
  const acceptKey = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acceptKey + '\r\n\r\n');
  sock.setNoDelay(true);
  const id = nextId++, p = { sock, name: 'Player ' + id, joined: Date.now(), bucket: MSGS_PER_SEC, last: Date.now(), seen: Date.now(), hello: false };
  p.room = room; room.players.set(id, p);
  if (room.host === null) { room.host = id; room.hostSeen = Date.now(); }
  let buf = Buffer.alloc(0), parts = [];
  sock.on('data', chunk => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 2) {
      const fin = buf[0] & 0x80, op = buf[0] & 0x0f, masked = buf[1] & 0x80;
      let len = buf[1] & 0x7f, off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      if (len > MAX_MSG) { sock.destroy(); return; }
      const need = off + (masked ? 4 : 0) + len; if (buf.length < need) return;
      let data = buf.subarray(off + (masked ? 4 : 0), need);
      if (masked) { const m = buf.subarray(off, off + 4); data = Buffer.from(data); for (let i = 0; i < data.length; i++) data[i] ^= m[i & 3]; }
      buf = buf.subarray(need);
      if (op === 0x8) { sock.end(); return; }                                     // close
      if (op === 0x9) { sock.write(Buffer.concat([Buffer.from([0x8a, data.length]), data])); continue; }   // ping -> pong
      if (op === 0xa) { p.alive = true; continue; }                              // pong
      if (op === 0x1 || op === 0x0) { parts.push(data); if (fin) { const text = Buffer.concat(parts).toString('utf8'); parts = []; onMessage(id, p, text); } }
    }
  });
  const gone = () => leave(id, room);
  sock.on('close', gone); sock.on('error', gone);
}

// ---------------- lobby logic ----------------
function cleanName(s) { return String(s || '').replace(/[^\w \-.!?']/g, '').trim().slice(0, 16) || 'Player'; }
function onMessage(id, p, text) {
  const room = p.room, lobby = room.lobby, host = room.host, players = room.players;
  // simple rate limit so one runaway client can't flood the room
  const now = Date.now(); p.seen = now; p.bucket = Math.min(MSGS_PER_SEC, p.bucket + (now - p.last) / 1000 * MSGS_PER_SEC); p.last = now;
  if (p.bucket < 1) return; p.bucket -= 1;
  let m; try { m = JSON.parse(text); } catch (e) { return; }
  if (!m || typeof m.t !== 'string') return;
  if (m.t === 'hello') {
    p.name = cleanName(m.name); p.hello = true;
    send(p, { t: 'welcome', id, host, room: room.name, target: FFA_TARGET, scores: lobby.scores, seed: lobby.seed, wave: lobby.wave && Object.assign({ age: Date.now() - lobby.wave.at }, lobby.wave), walls: [...lobby.walls], props: lobby.props, players: [...players].filter(([k, q]) => k !== id && q.hello).map(([k, q]) => ({ id: k, name: q.name })) });
    broadcast(room, { t: 'join', id, name: p.name }, id);
    return;
  }
  if (!p.hello) return;
  m.from = id;
  switch (m.t) {
    // the host's game is the source of truth for enemies and the wave clock
    case 'enemies': case 'kill': case 'ebullet':
      if (id === host) broadcast(room, m, id); return;
    case 'wave':
      if (id === host) { room.hostSeen = Date.now(); lobby.wave = { wave: m.wave, waveT: m.waveT, inter: m.inter, at: Date.now() }; broadcast(room, m, id); } return;
    case 'reset':   // the lobby cleared wave 20: start over on a new map
      if (id === host) { room.lobby = freshLobby(); broadcast(room, { t: 'reset', seed: room.lobby.seed }); } return;
    // damage to an enemy goes to the host, who owns its health
    case 'hit':
      if (host !== null && host !== id) send(players.get(host), m); return;
    // world changes are remembered for anyone who joins later
    case 'wall':
      if (Array.isArray(m.c)) for (const c of m.c) if (Number.isInteger(c)) lobby.walls.add(c);
      broadcast(room, m, id); return;
    case 'prop':
      if (Number.isInteger(m.k)) lobby.props[m.k] = m.dead ? { dead: 1 } : { i: m.i, j: m.j, ang: m.ang };
      broadcast(room, m, id); return;
    // Free For All: a hit goes to the player it hit, and the server keeps the score
    case 'pvp':
      if (room.name === 'ffa' && players.has(m.to)) send(players.get(m.to), m); return;
    case 'frag':
      if (room.name === 'ffa') frag(room, id, m); return;
    // everything else (player state, shots, explosions, fire, chat-free emotes) is just passed along
    case 'state': case 'shot': case 'boom': case 'fire': case 'down': case 'up':
      broadcast(room, m, id); return;
  }
}
function frag(room, vic, m) {
  const lobby = room.lobby, by = room.players.has(m.by) && m.by !== vic ? m.by : 0;
  if (lobby.ended) return;
  if (by) lobby.scores[by] = (lobby.scores[by] || 0) + 1;
  broadcast(room, { t: 'frag', by, vic, g: m.g, scores: lobby.scores });
  if (by && lobby.scores[by] >= FFA_TARGET) {
    lobby.ended = true; broadcast(room, { t: 'ffaEnd', id: by });
    setTimeout(() => { room.lobby = freshLobby(); broadcast(room, { t: 'reset', seed: room.lobby.seed, target: FFA_TARGET, scores: {} }); }, FFA_BREAK);
  }
}
function leave(id, room) {
  const p = room.players.get(id); if (!p) return;
  room.players.delete(id); try { p.sock.destroy(); } catch (e) { }
  broadcast(room, { t: 'leave', id });
  if (room.host === id) pickHost(room);
  if (!room.players.size) room.lobby = freshLobby();   // an empty lobby starts fresh next time
}

// the oldest player who is still active hosts
function pickHost(room, except) {
  const now = Date.now(); let best = null, oldest = Infinity;
  for (const [k, q] of room.players) if (k !== except && q.hello && now - q.seen < 3000 && q.joined < oldest) { oldest = q.joined; best = k; }
  if (best === null) for (const [k, q] of room.players) if (k !== except && q.hello && q.joined < oldest) { oldest = q.joined; best = k; }
  room.host = best; room.hostSeen = now;
  if (room.host !== null) broadcast(room, { t: 'host', id: room.host });
}
// a game that closed without saying goodbye can leave its connection open for a while behind Render's proxy:
// drop anyone silent for 15 s, and if the host stops running the waves for 4 s, hand hosting to someone else
setInterval(() => {
  const now = Date.now();
  for (const room of Object.values(rooms)) {
    for (const [id, p] of room.players) if (now - p.seen > 15000) leave(id, room);
    if (room.name === 'zombies' && room.host !== null && now - room.hostSeen > 4000 && room.players.size > 1) pickHost(room, room.host);
  }
}, 1000);
// keep-alive: ping everyone, drop anyone who stopped answering
setInterval(() => { for (const room of Object.values(rooms)) for (const [id, p] of room.players) { if (p.alive === false) { leave(id, room); continue; } p.alive = false; try { p.sock.write(Buffer.from([0x89, 0])); } catch (e) { leave(id, room); } } }, 20000);

const server = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('Live Fire lobby: ' + rooms.zombies.players.size + ' in Zombies, ' + rooms.ffa.players.size + ' in Free For All\n'); });
server.on('upgrade', (req, sock) => accept(req, sock));
server.listen(PORT, () => console.log('Live Fire lobby listening on ' + PORT));
