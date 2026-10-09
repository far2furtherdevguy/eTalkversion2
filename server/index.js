const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const srv = http.createServer(app);
const io = new Server(srv, { cors: { origin: '*' }, pingInterval: 8000, pingTimeout: 6000 });
app.use((_, res, next) => { res.set('Access-Control-Allow-Origin', '*'); next(); });
app.use(express.static(path.join(__dirname, '..', 'www')));
app.get('/health', (_, res) => res.send('ok'));

// ---- ICE ----
const FALLBACK_ICE = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun.relay.metered.ca:80' },
  { urls: ['turn:openrelay.metered.ca:80', 'turn:openrelay.metered.ca:443', 'turn:openrelay.metered.ca:443?transport=tcp', 'turns:openrelay.metered.ca:443?transport=tcp'],
    username: 'openrelayproject', credential: 'openrelayproject' },
];
let iceCache = { t: 0, v: null };
app.get('/ice', async (_, res) => {
  const { METERED_APP, METERED_KEY } = process.env;
  if (METERED_APP && METERED_KEY) {
    if (iceCache.v && Date.now() - iceCache.t < 3600e3) return res.json(iceCache.v);
    try {
      const r = await fetch(`https://${METERED_APP}.metered.live/api/v1/turn/credentials?apiKey=${METERED_KEY}`);
      if (r.ok) { iceCache = { t: Date.now(), v: await r.json() }; return res.json(iceCache.v); }
    } catch (e) { console.error('metered', e.message); }
  }
  res.json(FALLBACK_ICE);
});

// ---- Login verification (set SUPABASE_URL + SUPABASE_ANON_KEY on Render to stop impersonation) ----
const SB = process.env.SUPABASE_URL, KEY = process.env.SUPABASE_ANON_KEY;
async function verify(token, claim) {
  if (!SB || !KEY) return claim && claim.id ? claim : null; // unverified mode
  try {
    const h = { apikey: KEY, Authorization: 'Bearer ' + token };
    const u = await (await fetch(`${SB}/auth/v1/user`, { headers: h })).json();
    if (!u.id) return null;
    const p = await (await fetch(`${SB}/rest/v1/profiles?id=eq.${u.id}&select=id,username,avatar_url`, { headers: h })).json();
    return p[0] ? { id: p[0].id, username: p[0].username, avatar: p[0].avatar_url } : null;
  } catch (e) { return null; }
}

const rooms = new Map();   // pin -> Map(cid -> socket)
const online = new Map();  // userId -> { user, sockets:Set }
const calls = new Map();   // pin -> { from, to, t }
const broadcast = () => io.emit('online', [...online.values()].map((o) => o.user));

function endCall(pin, reason) {
  const c = calls.get(pin); if (!c) return;
  clearTimeout(c.t); calls.delete(pin);
  const to = online.get(c.to), from = online.get(c.from);
  if (to) to.sockets.forEach((x) => x.emit('incoming-end', { pin }));
  if (from && reason !== 'cancelled') from.sockets.forEach((x) => x.emit('call-end', { pin, reason }));
}
function logout(s) {
  if (!s.user) return;
  const o = online.get(s.user.id);
  if (o) { o.sockets.delete(s); if (!o.sockets.size) online.delete(s.user.id); }
  s.user = null; broadcast();
}
function drop(s) {
  const r = rooms.get(s.pin);
  if (r && r.get(s.cid) === s) {
    r.delete(s.cid);
    if (!r.size) rooms.delete(s.pin); else r.forEach((p) => p.emit('peer-left'));
  }
  s.pin = null;
}

io.on('connection', (s) => {
  s.on('login', (token, claim) => {
    s.loginP = (async () => {
      const u = await verify(token, claim);
      if (!u) return s.emit('login-fail');
      logout(s); s.user = u;
      let o = online.get(u.id);
      if (!o) online.set(u.id, (o = { user: u, sockets: new Set() }));
      o.user = u; o.sockets.add(s); broadcast();
    })();
  });
  s.on('logout', () => logout(s));

  s.on('call', async (toId) => {
    if (s.loginP) await s.loginP;
    const t = online.get(toId);
    if (!s.user || !t || toId === s.user.id) return s.emit('call-fail', 'That person is offline');
    let pin; do { pin = String(Math.floor(1e7 + Math.random() * 9e7)); } while (rooms.has(pin) || calls.has(pin));
    calls.set(pin, { from: s.user.id, to: toId, t: setTimeout(() => endCall(pin, 'missed'), 30000) });
    t.sockets.forEach((x) => x.emit('incoming', { pin, from: s.user }));
    s.emit('calling', { pin });
  });
  s.on('end-call', (pin) => {
    const c = calls.get(pin);
    if (c) endCall(pin, s.user && s.user.id === c.from ? 'cancelled' : 'declined');
  });

  s.on('join', async (pin, cid, named) => {
    if (named && s.loginP) await s.loginP;
    pin = String(pin);
    if (!/^\d{4,8}$/.test(pin) || !cid) return s.emit('err', 'PIN must be 4-8 digits');
    if (s.pin) drop(s);
    let r = rooms.get(pin);
    if (!r) rooms.set(pin, (r = new Map()));
    const old = r.get(cid);
    if (old && old !== s) { r.delete(cid); old.pin = null; old.emit('err', 'Joined from another tab/device'); old.disconnect(true); }
    if (r.size >= 2) return s.emit('err', 'Room is full. If you were just disconnected, retry in 15 seconds.');
    s.pin = pin; s.cid = cid; s.prof = named && s.user ? s.user : null; r.set(cid, s);
    if (r.size === 1) return s.emit('waiting');
    const c = calls.get(pin);
    if (c) { clearTimeout(c.t); calls.delete(pin); const to = online.get(c.to); if (to) to.sockets.forEach((x) => x !== s && x.emit('incoming-end', { pin })); }
    const arr = [...r.values()];
    arr.forEach((p) => p.emit('matched', { initiator: p !== s, peer: arr.find((x) => x !== p).prof }));
  });
  s.on('signal', (d) => { const r = rooms.get(s.pin); if (r) r.forEach((p) => p !== s && p.emit('signal', d)); });
  s.on('leave', () => drop(s));
  s.on('disconnect', () => { drop(s); logout(s); });
});

srv.listen(process.env.PORT || 3000, () => console.log('eTalk up'));
