/*
 * Tuner Proxy v2 — Node server (for a VPS inside the country you need)
 * ===================================================================
 * Same job as worker.js, but YOU choose the exit country by choosing
 * where this runs. This is the actual fix for geo-blocked streams:
 *
 *   India-only streams  →  run this on an India VPS  →  Indian exit IP.
 *
 * CHEAPEST INDIA VPS (free): Oracle Cloud Always-Free
 * (4 ARM cores + 24 GB RAM, Hyderabad or Mumbai region, free forever):
 *  1. cloud.oracle.com → free account → Compute → Ampere A1
 *     (region ap-hyderabad-1) → Ubuntu 22.04, open port 8080
 *  2. Copy this file over, run:  node server.js
 *     (needs Node 18+. Optional daemon: pm2 / systemd.)
 *  3. In the Tuner app: Settings → CORS proxy → Custom →
 *     paste  http://<your-vps-ip>:8080/?url=
 *     (Use a reverse proxy + cert for https if your page is https —
 *      mixed-content rules block http:// proxies from an https:// page.
 *      Easiest: Cloudflare Tunnel (free) in front of localhost:8080.)
 *
 * ENV OPTIONS:
 *   PORT=8080                listen port
 *   HOST=0.0.0.0             bind address (set 127.0.0.1 behind nginx)
 *   PUBLIC_BASE_URL=https://proxy.example.com   used for rewritten URLs
 *                              (recommended behind TLS terminators)
 *   ALLOW_LOCAL=1            also allow http(s)://localhost origins (dev)
 *   ALLOW_OPEN=1             disable the origin allowlist (NOT advised)
 *   SHARED_TOKEN below       optional ?token= or X-Proxy-Token secret
 *
 * SECURITY: set ALLOWED_ORIGINS to your site, or anyone can burn
 * your VPS bandwidth. Upgrade paths: http→https only at your reverse
 * proxy; this process speaks plain HTTP.
 */

const http = require('http');
const dns = require('dns');
const net = require('net');
const crypto = require('crypto');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');

const PORT = Number.parseInt(process.env.PORT || '8080', 10) || 8080;
const HOST = process.env.HOST || '0.0.0.0';
const PUBLIC_BASE_URL = String(process.env.PUBLIC_BASE_URL || '').replace(/\/+$/, '');
const ALLOWED_ORIGINS = ['https://sachindeepcleaning-coder.github.io'];
const ALLOW_LOCAL = process.env.ALLOW_LOCAL === '1';
const ALLOW_OPEN = process.env.ALLOW_OPEN === '1';
const SHARED_TOKEN = process.env.SHARED_TOKEN || '';
const REMOTE_TTL_MS = Math.max(1000, Number.parseInt(process.env.REMOTE_TTL_MS || '300000', 10) || 300000);
const REMOTE_PAGE = path.join(__dirname, 'remote.html');
const MAX_REDIRECTS = 5;
const FETCH_TIMEOUT_MS = 30000;
const MAX_MANIFEST_BYTES = 5 * 1024 * 1024;
const LOCAL_ORIGIN_RE = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/;

const STRIP_HEADERS = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'set-cookie',
  'set-cookie2',
  'access-control-allow-origin',
  'alt-svc',
  'strict-transport-security',
  'location',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
  'permissions-policy',
  'expect-ct',
  'report-to',
  'nel',
  'server',
  'x-powered-by',
  'connection',
  'transfer-encoding',
  'keep-alive',
  'via',
]);

function corsHeaders(origin, allowed) {
  const h = {
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type, Accept, Origin, X-Proxy-Token',
    'Access-Control-Max-Age': '86400',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges',
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff',
  };
  if (allowed && origin) h['Access-Control-Allow-Origin'] = origin;
  return h;
}

function blockedV4(ip) {
  const p = String(ip).split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  if (p[0] === 0 || p[0] === 10 || p[0] === 127) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 192 && p[1] === 0 && p[2] === 0) return true;
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
  if (p[0] === 198 && (p[1] === 18 || p[1] === 19)) return true;
  if (p[0] >= 224) return true;
  return false;
}

function blockedIp(raw) {
  const ip = String(raw || '').toLowerCase().replace(/^\[|\]$/g, '');
  const fam = net.isIP(ip);
  if (fam === 4) return blockedV4(ip);
  if (fam === 6) {
    if (ip === '::' || ip === '::1') return true;
    if (/^f[cd]/.test(ip)) return true;
    if (/^fe[89ab]/.test(ip)) return true;
    if (/^ff/.test(ip)) return true;
    const m = ip.match(/(?:^|:)ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (m) {
      const a = parseInt(m[1], 16);
      const b = parseInt(m[2], 16);
      return blockedV4([a >> 8, a & 255, b >> 8, b & 255].join('.'));
    }
    return false;
  }
  return true;
}

function hostBlocked(hostname) {
  let h = String(hostname || '').toLowerCase();
  if (h.startsWith('[') || h.includes(':')) return true;
  while (h.endsWith('.')) h = h.slice(0, -1);
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  const bad = ['.local', '.internal', '.home.arpa', '.lan', '.intranet', '.test', '.example', '.invalid', '.onion', '.arpa'];
  for (const s of bad) {
    if (h === s.slice(1) || h.endsWith(s)) return true;
  }
  if (net.isIP(h) === 4) return blockedV4(h);
  return false;
}

async function resolvesSafe(hostname) {
  try {
    const addrs = await dns.promises.lookup(hostname, { all: true, verbatim: true });
    if (!addrs.length) return false;
    for (const a of addrs) {
      if (blockedIp(a.address)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

async function safeTarget(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (hostBlocked(u.hostname)) return null;
  if (net.isIP(u.hostname.replace(/^\[|\]$/g, '')) === 0) {
    if (!(await resolvesSafe(u.hostname))) return null;
  }
  let authorization = '';
  if (u.username || u.password) {
    let user = u.username;
    let pass = u.password;
    try {
      user = decodeURIComponent(user);
      pass = decodeURIComponent(pass);
    } catch {
      /* keep raw */
    }
    authorization = 'Basic ' + Buffer.from(user + ':' + pass).toString('base64');
    u.username = '';
    u.password = '';
  }
  return { url: u.toString(), authorization };
}

function absUrl(rel, base) {
  try {
    return new URL(rel, base).href;
  } catch {
    return null;
  }
}

function rewriteManifest(text, manifestUrl, selfBase) {
  const out = String(text).replace(/^\uFEFF/, '').split(/\r?\n/);
  for (let i = 0; i < out.length; i++) {
    const t = out[i].trim();
    if (!t) continue;
    if (t.charAt(0) === '#') {
      out[i] = out[i].replace(/URI\s*=\s*(["'])([^"']+)\1/g, (mm, q, u) => {
        if (/^(data|blob):/i.test(u)) return mm;
        const abs = absUrl(u, manifestUrl);
        return abs ? `URI=${q}${selfBase}${encodeURIComponent(abs)}${q}` : mm;
      });
    } else {
      const abs = absUrl(t, manifestUrl);
      if (abs) out[i] = `${selfBase}${encodeURIComponent(abs)}`;
    }
  }
  return out.join('\n');
}

async function readCapped(body, cap) {
  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) {
      try {
        await reader.cancel();
      } catch {
        /* ignore */
      }
      return null;
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

/* ==========================================================================
 * Phone-as-remote (v1) — minimal WebSocket pairing, no external deps.
 *
 *   Desktop  ws://host:8080/remote-ws?role=tv      → creates a session
 *   Phone    ws://host:8080/remote-ws?role=phone&code=XXXXXXXX
 *
 * Messages: {type:'session'|'phone'|'cmd'|'state'|'new-code'|'error'}
 * Security model: trusted LAN. A random 8-char code gates the phone join,
 * the code expires after REMOTE_TTL_MS (5 min default), and only one phone
 * may be attached per TV. Sessions are in memory only.
 * ========================================================================== */
const WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const REMOTE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I lookalikes
const sessionsByCode = new Map(); // code -> { code, tv, phone, expiresAt, ttl }
const wsClients = new Map(); // socket -> client ctx

// Prefer Wi-Fi/Ethernet and private ranges; docker/vpn interfaces score low.
function lanAddresses() {
  const found = [];
  for (const [name, nets] of Object.entries(os.networkInterfaces())) {
    for (const n of nets || []) {
      if (!n || n.family !== 'IPv4' || n.internal || /^169\.254\./.test(n.address)) continue;
      let score = 0;
      if (/^(wl|wlan|wlp|en|eth)/i.test(name)) score += 3;
      if (/^192\.168\./.test(n.address)) score += 2;
      else if (/^10\./.test(n.address)) score += 1;
      found.push({ address: n.address, score });
    }
  }
  found.sort((a, b) => b.score - a.score);
  return [...new Set(found.map((f) => f.address))];
}

function serveRemote(res) {
  fs.readFile(REMOTE_PAGE, (err, buf) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('remote.html not found next to server.js');
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(buf);
  });
}

function serveLanIp(res) {
  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(JSON.stringify({ port: PORT, ips: lanAddresses() }));
}

// ---- tiny RFC 6455 helpers (text frames + ping/pong/close only) ----
function wsFrame(opcode, payload) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload));
  const len = data.length;
  let head;
  if (len < 126) {
    head = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    head = Buffer.alloc(4);
    head[0] = 0x80 | opcode;
    head[1] = 126;
    head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x80 | opcode;
    head[1] = 127;
    head.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([head, data]);
}

function wsSend(client, obj) {
  if (!client || !client.alive) return;
  try {
    client.socket.write(wsFrame(0x1, typeof obj === 'string' ? obj : JSON.stringify(obj)));
  } catch {
    /* socket gone */
  }
}

function wsEnd(client, code, reason) {
  if (!client) return;
  try {
    const text = String(reason || '');
    const body = Buffer.alloc(2 + Buffer.byteLength(text));
    body.writeUInt16BE(code || 1000, 0);
    body.write(text, 2);
    client.socket.write(wsFrame(0x8, body));
  } catch {
    /* ignore */
  }
  setTimeout(() => {
    try {
      client.socket.end();
    } catch {
      /* ignore */
    }
  }, 60);
}

function makeCode() {
  for (;;) {
    let code = '';
    for (let i = 0; i < 8; i++) code += REMOTE_ALPHABET[crypto.randomInt(REMOTE_ALPHABET.length)];
    if (!sessionsByCode.has(code)) return code;
  }
}

function sessionUrls(code) {
  const p = '/remote?code=' + code;
  const urls = lanAddresses().map((ip) => 'http://' + ip + ':' + PORT + p);
  urls.push('http://127.0.0.1:' + PORT + p);
  return urls;
}

function sendSession(client) {
  const s = client && client.session;
  if (!s) return;
  wsSend(client, {
    type: 'session',
    code: s.code,
    ttl: s.ttl,
    expiresAt: s.expiresAt,
    joinPath: '/remote?code=' + s.code,
    urls: sessionUrls(s.code),
  });
}

function failClient(client, message) {
  wsSend(client, { type: 'error', message });
  wsEnd(client, 1008, message);
}

function createTvSession(client) {
  const code = makeCode();
  client.session = {
    code,
    tv: client,
    phone: null,
    ttl: REMOTE_TTL_MS,
    expiresAt: Date.now() + REMOTE_TTL_MS,
  };
  sessionsByCode.set(code, client.session);
  sendSession(client);
  console.log('[tuner-remote] session ' + code + ' created');
}

function joinPhoneSession(client, rawCode) {
  const code = String(rawCode || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  const session = sessionsByCode.get(code);
  if (!session) return failClient(client, 'Code not found. Check the 8 characters on the TV.');
  if (!session.tv || !session.tv.alive) {
    sessionsByCode.delete(code);
    return failClient(client, 'The TV is offline. Reload the TV and try a new code.');
  }
  if (Date.now() > session.expiresAt) return failClient(client, 'This code expired. Ask the TV for a new one.');
  if (session.phone && session.phone.alive) return failClient(client, 'Another phone is already connected to this TV.');
  session.phone = client;
  client.session = session;
  wsSend(client, { type: 'joined', code });
  wsSend(session.tv, { type: 'phone', connected: true });
  console.log('[tuner-remote] phone joined ' + code);
}

function cleanupClient(client) {
  if (!client.alive) return;
  client.alive = false;
  const s = client.session;
  if (!s) return;
  if (client.role === 'tv') {
    sessionsByCode.delete(s.code);
    if (s.phone && s.phone.alive) {
      wsSend(s.phone, { type: 'error', message: 'The TV disconnected.' });
      wsEnd(s.phone, 1001, 'TV disconnected');
    }
    console.log('[tuner-remote] session ' + s.code + ' closed');
  } else {
    if (s.phone === client) s.phone = null;
    if (s.tv && s.tv.alive) wsSend(s.tv, { type: 'phone', connected: false });
  }
}

function handleRemoteMessage(client, text) {
  if (text.length > 4096) return;
  const now = Date.now();
  client.hits = (client.hits || []).filter((t) => now - t < 5000);
  if (client.hits.length > 60) return failClient(client, 'Too many messages');
  client.hits.push(now);

  let msg;
  try {
    msg = JSON.parse(text);
  } catch {
    return;
  }
  if (!msg || typeof msg.type !== 'string') return;

  if (msg.type === 'cmd' && client.role === 'phone' && client.session) {
    // Phone only ever sends commands; the TV decides what to do.
    const allowed = ['chup', 'chdown', 'volup', 'voldown', 'mute', 'power'];
    if (!allowed.includes(msg.action)) return;
    const tv = client.session.tv;
    if (tv && tv.alive) wsSend(tv, { type: 'cmd', action: msg.action });
  } else if (msg.type === 'state' && client.role === 'tv' && client.session) {
    // TV is authoritative — mirror its state to the phone.
    const phone = client.session.phone;
    if (phone && phone.alive) wsSend(phone, { type: 'state', state: msg.state || {} });
  } else if (msg.type === 'new-code' && client.role === 'tv' && client.session) {
    const s = client.session;
    sessionsByCode.delete(s.code);
    s.code = makeCode();
    s.expiresAt = Date.now() + s.ttl;
    sessionsByCode.set(s.code, s);
    sendSession(client);
  }
}

const server = http.createServer(async (req, res) => {
  res.on('error', () => {});
  const origin = req.headers.origin || '';

  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders(origin, true));
    res.end();
    return;
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, corsHeaders(origin, true));
    res.end('Only GET/HEAD');
    return;
  }

  const reqUrl = new URL(req.url, 'http://local');

  // --- Phone remote endpoints (not part of the CORS proxy) ---
  if (reqUrl.pathname === '/remote' || reqUrl.pathname === '/remote.html') {
    serveRemote(res);
    return;
  }
  if (reqUrl.pathname === '/api/lan-ip') {
    serveLanIp(res);
    return;
  }

  const target = reqUrl.searchParams.get('url');
  const token = req.headers['x-proxy-token'] || reqUrl.searchParams.get('token') || '';
  const referer = req.headers.referer || '';

  let refOrigin = '';
  try {
    refOrigin = referer ? new URL(referer).origin : '';
  } catch {
    refOrigin = '';
  }
  const allowed =
    ALLOW_OPEN ||
    (SHARED_TOKEN && token === SHARED_TOKEN) ||
    ALLOWED_ORIGINS.includes(origin) ||
    (refOrigin && ALLOWED_ORIGINS.includes(refOrigin)) ||
    (ALLOW_LOCAL && (LOCAL_ORIGIN_RE.test(origin) || LOCAL_ORIGIN_RE.test(refOrigin)));

  const cors = corsHeaders(origin, !!allowed);
  if (!allowed) {
    res.writeHead(403, cors);
    res.end('Origin not allowed');
    return;
  }
  if (!target) {
    res.writeHead(400, cors);
    res.end('Usage: ?url=<encoded-stream-url>');
    return;
  }
  if (target.length > 8000) {
    res.writeHead(400, cors);
    res.end('url too long');
    return;
  }

  const ac = new AbortController();
  const clientGone = () => {
    try {
      ac.abort();
    } catch {
      /* ignore */
    }
  };
  req.on('close', clientGone);
  const killer = setTimeout(clientGone, FETCH_TIMEOUT_MS);

  try {
    let hop = await safeTarget(target);
    if (!hop) {
      res.writeHead(403, cors);
      res.end('Blocked target');
      return;
    }

    let method = req.method;
    let up = null;
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      const headers = {
        'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0 (compatible; TunerProxy/2.0)',
        'Accept-Encoding': 'identity',
      };
      for (const h of ['range', 'accept', 'accept-language', 'if-range', 'if-none-match', 'if-modified-since']) {
        if (req.headers[h]) headers[h] = req.headers[h];
      }
      if (hop.authorization) headers.Authorization = hop.authorization;

      up = await fetch(hop.url, { method, headers, redirect: 'manual', signal: ac.signal });

      const isRedirect = up.status >= 300 && up.status < 400 && up.headers.get('location');
      if (!isRedirect) break;
      if (i === MAX_REDIRECTS) {
        try {
          if (up.body) await up.body.cancel();
        } catch {
          /* ignore */
        }
        res.writeHead(502, cors);
        res.end('Too many redirects');
        return;
      }
      let loc;
      try {
        loc = new URL(up.headers.get('location'), hop.url).toString();
      } catch {
        loc = null;
      }
      const nextHop = loc ? await safeTarget(loc) : null;
      try {
        if (up.body) await up.body.cancel();
      } catch {
        /* ignore */
      }
      if (!nextHop) {
        res.writeHead(403, cors);
        res.end('Blocked redirect target');
        return;
      }
      let sameOrigin = false;
      try {
        sameOrigin = new URL(hop.url).origin === new URL(nextHop.url).origin;
      } catch {
        sameOrigin = false;
      }
      nextHop.authorization = sameOrigin ? hop.authorization : '';
      hop = nextHop;
      if (up.status === 303) method = 'GET';
    }

    if (!up) {
      res.writeHead(502, cors);
      res.end('Upstream fetch failed');
      return;
    }

    const outHeaders = {};
    up.headers.forEach((v, k) => {
      const kl = String(k).toLowerCase();
      if (!STRIP_HEADERS.has(kl)) outHeaders[kl] = v;
    });
    for (const k of Object.keys(cors)) outHeaders[String(k).toLowerCase()] = cors[k];

    let finalUrl = hop.url;
    try {
      finalUrl = up.url || hop.url;
    } catch {
      /* ignore */
    }
    let pathname = '';
    try {
      pathname = new URL(finalUrl).pathname;
    } catch {
      pathname = '';
    }
    const ct = (up.headers.get('content-type') || '').toLowerCase();
    const ctManifest = /mpegurl|vnd\.apple/i.test(ct);
    const pathManifest = /\.m3u8?$/i.test(pathname);
    const textLike = /^text\//i.test(ct);
    const maybeText = ctManifest || pathManifest || textLike;
    const clen = Number.parseInt(up.headers.get('content-length') || '0', 10) || 0;
    const canBuffer = clen === 0 || clen <= MAX_MANIFEST_BYTES;

    if (req.method === 'GET' && maybeText && up.status !== 206 && up.status < 400 && canBuffer && up.body) {
      const buf = await readCapped(up.body, MAX_MANIFEST_BYTES);
      if (buf) {
        const text = buf.toString('utf8');
        if (/^\uFEFF?#EXTM3U/.test(text)) {
          const host = PUBLIC_BASE_URL
            ? PUBLIC_BASE_URL
            : `${req.socket.encrypted ? 'https' : 'http'}://${req.headers.host || 'localhost:' + PORT}`;
          const selfBase = host.replace(/\/+$/, '') + '/?url=';
          const rewritten = rewriteManifest(text, finalUrl, selfBase);
          for (const k of ['content-length', 'content-encoding', 'etag', 'last-modified', 'expires', 'accept-ranges', 'content-range']) {
            delete outHeaders[k];
          }
          outHeaders['content-type'] = 'application/vnd.apple.mpegurl';
          outHeaders['cache-control'] = 'no-store';
          res.writeHead(up.status, outHeaders);
          res.end(rewritten);
          return;
        }
        outHeaders['content-length'] = buf.length;
        res.writeHead(up.status, outHeaders);
        res.end(buf);
        return;
      }
    }

    res.writeHead(up.status, outHeaders);
    if (req.method === 'HEAD' || !up.body) {
      res.end();
      return;
    }
    const body = Readable.fromWeb(up.body);
    body.on('error', () => {
      try {
        res.destroy();
      } catch {
        /* ignore */
      }
    });
    body.pipe(res);
  } catch {
    if (!res.headersSent) {
      const code = ac.signal.aborted ? 504 : 502;
      try {
        res.writeHead(code, cors);
        res.end('Upstream fetch failed');
      } catch {
        /* client gone */
      }
    } else {
      try {
        res.destroy();
      } catch {
        /* ignore */
      }
    }
  } finally {
    clearTimeout(killer);
    req.removeListener('close', clientGone);
  }
});

server.on('upgrade', (req, socket) => {
  let u;
  try {
    u = new URL(req.url, 'http://local');
  } catch {
    socket.destroy();
    return;
  }
  const key = req.headers['sec-websocket-key'];
  if (u.pathname !== '/remote-ws' || !key || String(req.headers.upgrade || '').toLowerCase() !== 'websocket') {
    socket.destroy();
    return;
  }
  const accept = crypto.createHash('sha1').update(key + WS_MAGIC).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      'Sec-WebSocket-Accept: ' + accept + '\r\n' +
      '\r\n'
  );
  socket.setNoDelay(true);

  const client = {
    socket,
    role: u.searchParams.get('role') === 'phone' ? 'phone' : 'tv',
    alive: true,
    session: null,
    lastSeen: Date.now(),
    buf: Buffer.alloc(0),
    hits: [],
  };
  wsClients.set(socket, client);

  socket.on('data', (chunk) => {
    client.buf = Buffer.concat([client.buf, chunk]);
    for (;;) {
      const b = client.buf;
      if (b.length < 2) return;
      const fin = (b[0] & 0x80) !== 0;
      const opcode = b[0] & 0x0f;
      const masked = (b[1] & 0x80) !== 0;
      let len = b[1] & 0x7f;
      let off = 2;
      if (len === 126) {
        if (b.length < 4) return;
        len = b.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (b.length < 10) return;
        len = Number(b.readBigUInt64BE(2));
        off = 10;
      }
      if (len > 65536) {
        wsEnd(client, 1009, 'Message too big');
        return;
      }
      const need = off + (masked ? 4 : 0) + len;
      if (b.length < need) return;
      let payload = b.subarray(off + (masked ? 4 : 0), need);
      if (masked) {
        const mask = b.subarray(off, off + 4);
        payload = Buffer.from(payload.map((v, i) => v ^ mask[i & 3]));
      }
      client.buf = b.subarray(need);
      if (opcode === 0x8) {
        cleanupClient(client);
        wsClients.delete(socket);
        try {
          socket.end();
        } catch {
          /* ignore */
        }
        return;
      }
      if (opcode === 0x9) {
        try {
          socket.write(wsFrame(0xa, payload));
        } catch {
          /* ignore */
        }
        continue;
      }
      if (opcode === 0xa) {
        client.lastSeen = Date.now();
        continue;
      }
      if (opcode === 0x1 && fin) {
        client.lastSeen = Date.now();
        handleRemoteMessage(client, payload.toString('utf8'));
      }
    }
  });

  const onGone = () => {
    cleanupClient(client);
    wsClients.delete(socket);
  };
  socket.on('close', onGone);
  socket.on('error', onGone);

  if (client.role === 'tv') createTvSession(client);
  else joinPhoneSession(client, u.searchParams.get('code'));
});

// Drop dead sockets; expired sessions stay until the TV disconnects so a
// connected phone keeps working past the join-code TTL.
setInterval(() => {
  const now = Date.now();
  for (const client of wsClients.values()) {
    if (!client.alive) continue;
    if (now - client.lastSeen > 70000) {
      cleanupClient(client);
      wsClients.delete(client.socket);
      try {
        client.socket.destroy();
      } catch {
        /* ignore */
      }
      continue;
    }
    try {
      client.socket.write(wsFrame(0x9, Buffer.alloc(0)));
    } catch {
      /* ignore */
    }
  }
}, 25000).unref();

server.on('clientError', (err, socket) => {
  try {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  } catch {
    /* ignore */
  }
});

if (!ALLOW_OPEN && !ALLOWED_ORIGINS.length && !process.env.SHARED_TOKEN) {
  console.warn('[tuner-proxy] ALLOWED_ORIGINS is empty and ALLOW_OPEN is not set — proxy will reject everything.');
}

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
});

server.listen(PORT, HOST, () => {
  console.log(`Tuner proxy on ${HOST}:${PORT}  (exit IP = this VPS country)`);
  if (ALLOW_LOCAL) console.log('ALLOW_LOCAL=1 — localhost origins permitted (development mode)');
  if (ALLOW_OPEN) console.log('ALLOW_OPEN=1 — origin allowlist disabled (open proxy!)');
});
