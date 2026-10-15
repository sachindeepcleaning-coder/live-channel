/*
 * Tuner Proxy — Cloudflare Worker
 * ================================
 * Fixes in the browser what the app alone cannot:
 *  1. CORS blocks (adds Access-Control-Allow-Origin)
 *  2. Mixed content (http streams become https through the worker)
 *  3. Multi-level HLS (rewrites relative playlist URLs so nested
 *     manifests keep working — dumb ?url= proxies break these)
 *
 * DEPLOY (no CLI, ~2 minutes, free):
 *  1. dash.cloudflare.com → Workers & Pages → Create → Create Worker → Deploy → Edit code
 *  2. Paste this whole file → Save and Deploy
 *  3. Set ALLOWED_ORIGINS below to your site (already set for this repo's Pages URL)
 *  4. In the Tuner app: Settings → CORS proxy → Custom →
 *     paste  https://<your-worker>.workers.dev/?url=
 *
 * GEO-BLOCKS: Workers exit from Cloudflare's global network (any country),
 * so this does NOT guarantee an Indian exit IP. For country-locked streams,
 * use server.js on a VPS inside that country instead (see file header there).
 */

const CONFIG = {
  // Only these site origins may use the proxy. Add your domains here.
  // Empty array = open proxy (anyone can use it — you pay the bandwidth).
  ALLOWED_ORIGINS: ['https://sachindeepcleaning-coder.github.io'],

  // Optional shared secret: requests may also pass ?token=SECRET.
  // Leave '' to disable.
  SHARED_TOKEN: '',
};

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type, Accept, Origin',
    'Access-Control-Max-Age': '86400',
  };
}

function originAllowed(req, urlObj) {
  if (CONFIG.ALLOWED_ORIGINS.length === 0) return true;
  const origin = req.headers.get('Origin') || '';
  const referer = req.headers.get('Referer') || '';
  if (CONFIG.ALLOWED_ORIGINS.includes(origin)) return true;
  if (CONFIG.ALLOWED_ORIGINS.some((o) => referer.startsWith(o))) return true;
  if (CONFIG.SHARED_TOKEN && urlObj.searchParams.get('token') === CONFIG.SHARED_TOKEN) return true;
  return false;
}

// SSRF guard: never fetch loopback / private / cloud-metadata targets.
function isBlockedHost(hostname) {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(h)) {
    const p = h.split('.').map(Number);
    if (p[0] === 10) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 127) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 0) return true;
  }
  if (h === 'metadata.google.internal' || h.endsWith('.internal')) return true;
  return false;
}

function absUrl(rel, base) {
  try {
    return new URL(rel, base).href;
  } catch {
    return null;
  }
}

// Rewrite every URI in an m3u8 to route through THIS worker (absolute).
function rewriteManifest(text, manifestUrl, selfBase) {
  const out = text.split(/\r?\n/);
  for (let i = 0; i < out.length; i++) {
    const line = out[i];
    if (!line) continue;
    if (line.charAt(0) === '#') {
      out[i] = line.replace(/URI="([^"]+)"/g, (m, u) => {
        if (u.startsWith('data:')) return m;
        const abs = /^(https?:)?\/\//i.test(u) ? u : absUrl(u, manifestUrl);
        return abs ? `URI="${selfBase}${encodeURIComponent(abs)}"` : m;
      });
    } else {
      const t = line.trim();
      const abs = /^(https?:)?\/\//i.test(t) ? t : absUrl(t, manifestUrl);
      if (abs) out[i] = `${selfBase}${encodeURIComponent(abs)}`;
    }
  }
  return out.join('\n');
}

export default {
  async fetch(req) {
    const urlObj = new URL(req.url);
    const origin = req.headers.get('Origin') || '';
    const cors = corsHeaders(CONFIG.ALLOWED_ORIGINS.includes(origin) ? origin : '*');

    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return new Response('Only GET/HEAD', { status: 405, headers: cors });
    }

    const target = urlObj.searchParams.get('url');
    if (!target) {
      return new Response('Usage: ?url=<encoded-stream-url>', { status: 400, headers: cors });
    }
    let dest;
    try {
      dest = new URL(target);
    } catch {
      return new Response('Bad url param', { status: 400, headers: cors });
    }
    if (dest.protocol !== 'http:' && dest.protocol !== 'https:') {
      return new Response('Only http/https targets', { status: 400, headers: cors });
    }
    if (isBlockedHost(dest.hostname)) {
      return new Response('Blocked target', { status: 403, headers: cors });
    }
    if (!originAllowed(req, urlObj)) {
      return new Response('Origin not allowed — set ALLOWED_ORIGINS in the worker', {
        status: 403,
        headers: cors,
      });
    }

    // Forward range/accept so seeking and quality selection keep working.
    const fwd = new Headers();
    for (const h of ['range', 'accept', 'accept-language']) {
      const v = req.headers.get(h);
      if (v) fwd.set(h, v);
    }
    fwd.set('User-Agent', 'Mozilla/5.0 (compatible; TunerProxy/1.0)');
    fwd.delete('cookie');
    fwd.delete('authorization');

    let up;
    try {
      up = await fetch(dest.toString(), {
        method: req.method,
        headers: fwd,
        redirect: 'follow',
      });
    } catch (e) {
      return new Response('Upstream fetch failed: ' + (e && e.message), {
        status: 502,
        headers: cors,
      });
    }

    const resHeaders = new Headers(up.headers);
    for (const [k, v] of Object.entries(cors)) resHeaders.set(k, v);
    // Strip headers that break proxied playback
    for (const h of [
      'content-security-policy',
      'content-security-policy-report-only',
      'x-frame-options',
      'access-control-allow-origin',
    ]) {
      resHeaders.delete(h);
    }

    const ct = up.headers.get('content-type') || '';
    const isManifest =
      /mpegurl|vnd\.apple/i.test(ct) || /\.m3u8($|[?#])/i.test(dest.pathname);

    if (isManifest && req.method === 'GET') {
      const text = await up.text();
      const selfBase = `${urlObj.origin}${urlObj.pathname}?url=`;
      const rewritten = rewriteManifest(text, dest.toString(), selfBase);
      resHeaders.set('content-type', 'application/vnd.apple.mpegurl');
      resHeaders.delete('content-length');
      return new Response(rewritten, { status: up.status, headers: resHeaders });
    }

    return new Response(req.method === 'HEAD' ? null : up.body, {
      status: up.status,
      headers: resHeaders,
    });
  },
};
