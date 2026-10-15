/*
 * Tuner Proxy — Node server (for a VPS inside the country you need)
 * =================================================================
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
 * SECURITY: set ALLOWED_ORIGINS to your site, or anyone can burn
 * your VPS bandwidth. Optional shared ?token= supported.
 */

const http = require('http');

const PORT = process.env.PORT || 8080;
const ALLOWED_ORIGINS = ['https://sachindeepcleaning-coder.github.io']; // [] = open proxy (not advised)
const SHARED_TOKEN = ''; // e.g. 's3cret' → also accept ?token=s3cret

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin':
      origin && ALLOWED_ORIGINS.includes(origin) ? origin : '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type, Accept, Origin',
    'Access-Control-Max-Age': '86400',
  };
}

function isBlockedHost(hostname) {
  const h = String(hostname).toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const p = m.slice(1).map(Number);
    if (p[0] === 10) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 127 || (p[0] === 169 && p[1] === 254) || p[0] === 0) return true;
  }
  return false;
}

function absUrl(rel, base) {
  try {
    return new URL(rel, base).href;
  } catch {
    return null;
  }
}

function rewriteManifest(text, manifestUrl, selfBase) {
  const out = text.split(/\r?\n/);
  for (let i = 0; i < out.length; i++) {
    const line = out[i];
    if (!line) continue;
    if (line.charAt(0) === '#') {
      out[i] = line.replace(/URI="([^"]+)"/g, (mm, u) => {
        if (u.startsWith('data:')) return mm;
        const abs = /^(https?:)?\/\//i.test(u) ? u : absUrl(u, manifestUrl);
        return abs ? `URI="${selfBase}${encodeURIComponent(abs)}"` : mm;
      });
    } else {
      const t = line.trim();
      const abs = /^(https?:)?\/\//i.test(t) ? t : absUrl(t, manifestUrl);
      if (abs) out[i] = `${selfBase}${encodeURIComponent(abs)}`;
    }
  }
  return out.join('\n');
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin || '';
  const cors = corsHeaders(origin);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, cors);
    res.end();
    return;
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, cors);
    res.end('Only GET/HEAD');
    return;
  }

  const reqUrl = new URL(req.url, 'http://local');
  const target = reqUrl.searchParams.get('url');
  if (!target) {
    res.writeHead(400, cors);
    res.end('Usage: ?url=<encoded-stream-url>');
    return;
  }
  let dest;
  try {
    dest = new URL(target);
  } catch {
    res.writeHead(400, cors);
    res.end('Bad url param');
    return;
  }
  if (dest.protocol !== 'http:' && dest.protocol !== 'https:') {
    res.writeHead(400, cors);
    res.end('Only http/https targets');
    return;
  }
  if (isBlockedHost(dest.hostname)) {
    res.writeHead(403, cors);
    res.end('Blocked target');
    return;
  }
  const referer = req.headers.referer || '';
  const originOk =
    ALLOWED_ORIGINS.length === 0 ||
    ALLOWED_ORIGINS.includes(origin) ||
    ALLOWED_ORIGINS.some((o) => referer.startsWith(o)) ||
    (SHARED_TOKEN && reqUrl.searchParams.get('token') === SHARED_TOKEN);
  if (!originOk) {
    res.writeHead(403, cors);
    res.end('Origin not allowed');
    return;
  }

  const headers = { 'User-Agent': 'Mozilla/5.0 (compatible; TunerProxy/1.0)' };
  for (const h of ['range', 'accept', 'accept-language']) {
    if (req.headers[h]) headers[h] = req.headers[h];
  }

  let up;
  try {
    up = await fetch(dest.toString(), {
      method: req.method,
      headers,
      redirect: 'follow',
    });
  } catch (e) {
    res.writeHead(502, cors);
    res.end('Upstream fetch failed');
    return;
  }

  const outHeaders = { ...cors };
  up.headers.forEach((v, k) => {
    const kl = k.toLowerCase();
    if (
      [
        'content-security-policy',
        'x-frame-options',
        'access-control-allow-origin',
        'connection',
        'transfer-encoding',
      ].includes(kl)
    ) {
      return;
    }
    outHeaders[k] = v;
  });

  const ct = up.headers.get('content-type') || '';
  const isManifest =
    /mpegurl|vnd\.apple/i.test(ct) || /\.m3u8($|[?#])/i.test(dest.pathname);

  if (isManifest && req.method === 'GET') {
    const text = await up.text();
    const host = req.headers.host || `localhost:${PORT}`;
    const selfBase = `http://${host}/?url=`;
    const rewritten = rewriteManifest(text, dest.toString(), selfBase);
    delete outHeaders['content-length'];
    outHeaders['content-type'] = 'application/vnd.apple.mpegurl';
    res.writeHead(up.status, outHeaders);
    res.end(rewritten);
    return;
  }

  res.writeHead(up.status, outHeaders);
  if (req.method === 'HEAD' || !up.body) {
    res.end();
    return;
  }
  const reader = up.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!res.write(value)) await new Promise((r) => res.once('drain', r));
    }
  } catch {
    /* client went away */
  }
  res.end();
});

server.listen(PORT, () => console.log(`Tuner proxy on :${PORT}  (exit IP = this VPS country)`));
