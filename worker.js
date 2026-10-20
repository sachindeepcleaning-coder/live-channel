/*
 * Tuner Proxy v2 — Cloudflare Worker
 * ==================================
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
 *
 * NOTE: Workers have no DNS API, so the SSRF guard is host-string based
 * (per redirect hop). For hard targets use the Node proxy, which also
 * resolves and vets every IP.
 */

const CONFIG = {
  // Only these site origins may use the proxy. Add your domains here.
  // Empty array + ALLOW_OPEN=false = reject everything (fail closed).
  ALLOWED_ORIGINS: ['https://sachindeepcleaning-coder.github.io'],

  // Set true only if you really want an open proxy (you pay the bandwidth).
  ALLOW_OPEN: false,

  // Optional shared secret: requests may also pass ?token=SECRET
  // or the X-Proxy-Token header. Leave '' to disable.
  SHARED_TOKEN: '',

  MAX_REDIRECTS: 3,
  FETCH_TIMEOUT_MS: 25000,
  MAX_MANIFEST_BYTES: 5 * 1024 * 1024,
};

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

function isBlockedHost(hostname) {
  let h = String(hostname || '').toLowerCase();
  if (h.startsWith('[') || h.includes(':')) return true;
  while (h.endsWith('.')) h = h.slice(0, -1);
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h === 'metadata.google.internal' || h.endsWith('.internal')) return true;
  const bad = ['.local', '.home.arpa', '.lan', '.intranet', '.test', '.example', '.invalid', '.onion', '.arpa'];
  for (const s of bad) {
    if (h === s.slice(1) || h.endsWith(s)) return true;
  }
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const p = m.slice(1).map(Number);
    if (p.some((n) => n > 255)) return true;
    if (p[0] === 0 || p[0] === 10 || p[0] === 127) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 192 && p[1] === 0 && p[2] === 0) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
    if (p[0] === 198 && (p[1] === 18 || p[1] === 19)) return true;
    if (p[0] >= 224) return true;
  }
  return false;
}

function safeTarget(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (isBlockedHost(u.hostname)) return null;
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
    let encoded = '';
    try {
      encoded = btoa(user + ':' + pass);
    } catch {
      encoded = '';
    }
    authorization = encoded ? 'Basic ' + encoded : '';
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
    chunks.push(value);
  }
  const size = chunks.reduce((n, c) => n + c.byteLength, 0);
  const merged = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.byteLength;
  }
  return merged;
}

export default {
  async fetch(req) {
    const urlObj = new URL(req.url);
    const origin = req.headers.get('Origin') || '';
    const referer = req.headers.get('Referer') || '';
    const token = req.headers.get('X-Proxy-Token') || urlObj.searchParams.get('token') || '';

    // Decide the allowlist once, so preflight replies agree with the real
    // request instead of echoing an arbitrary origin.
    let refOrigin = '';
    try {
      refOrigin = referer ? new URL(referer).origin : '';
    } catch {
      refOrigin = '';
    }
    const allowed =
      CONFIG.ALLOW_OPEN ||
      (CONFIG.SHARED_TOKEN && token === CONFIG.SHARED_TOKEN) ||
      CONFIG.ALLOWED_ORIGINS.includes(origin) ||
      (refOrigin && CONFIG.ALLOWED_ORIGINS.includes(refOrigin));
    const cors = corsHeaders(origin, !!allowed);

    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return new Response('Only GET/HEAD', { status: 405, headers: cors });
    }
    if (!allowed) {
      return new Response('Origin not allowed — set ALLOWED_ORIGINS in the worker', { status: 403, headers: cors });
    }

    const target = urlObj.searchParams.get('url');
    if (!target) {
      return new Response('Usage: ?url=<encoded-stream-url>', { status: 400, headers: cors });
    }
    if (target.length > 8000) {
      return new Response('url too long', { status: 400, headers: cors });
    }

    const ac = new AbortController();
    const killer = setTimeout(() => {
      try {
        ac.abort();
      } catch {
        /* ignore */
      }
    }, CONFIG.FETCH_TIMEOUT_MS);

    try {
      let hop = safeTarget(target);
      if (!hop) return new Response('Blocked target', { status: 403, headers: cors });

      let method = req.method;
      let up = null;
      for (let i = 0; i <= CONFIG.MAX_REDIRECTS; i++) {
        const fwd = new Headers();
        for (const h of ['range', 'accept', 'accept-language', 'if-range', 'if-none-match', 'if-modified-since']) {
          const v = req.headers.get(h);
          if (v) fwd.set(h, v);
        }
        fwd.set('User-Agent', req.headers.get('User-Agent') || 'Mozilla/5.0 (compatible; TunerProxy/2.0)');
        fwd.set('Accept-Encoding', 'identity');
        if (hop.authorization) fwd.set('Authorization', hop.authorization);

        up = await fetch(hop.url, { method, headers: fwd, redirect: 'manual', signal: ac.signal });

        const isRedirect = up.status >= 300 && up.status < 400 && up.headers.get('Location');
        if (!isRedirect) break;
        if (i === CONFIG.MAX_REDIRECTS) {
          try {
            if (up.body) await up.body.cancel();
          } catch {
            /* ignore */
          }
          return new Response('Too many redirects', { status: 502, headers: cors });
        }
        let loc = null;
        try {
          loc = new URL(up.headers.get('Location'), hop.url).toString();
        } catch {
          loc = null;
        }
        const nextHop = loc ? safeTarget(loc) : null;
        try {
          if (up.body) await up.body.cancel();
        } catch {
          /* ignore */
        }
        if (!nextHop) return new Response('Blocked redirect target', { status: 403, headers: cors });
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

      if (!up) return new Response('Upstream fetch failed', { status: 502, headers: cors });

      const finalUrl = up.url || hop.url;
      let pathname = '';
      try {
        pathname = new URL(finalUrl).pathname;
      } catch {
        pathname = '';
      }
      let ct = (up.headers.get('content-type') || '').toLowerCase();
      const ctManifest = /mpegurl|vnd\.apple/i.test(ct);
      const pathManifest = /\.m3u8?$/i.test(pathname);
      const textLike = /^text\//i.test(ct);
      const maybeText = ctManifest || pathManifest || textLike;
      const clen = Number.parseInt(up.headers.get('content-length') || '0', 10) || 0;
      const canBuffer = clen === 0 || clen <= CONFIG.MAX_MANIFEST_BYTES;

      // A partial manifest cannot be rewritten safely — the same URL is
      // re-requested without the Range header so the whole playlist is buffered.
      if (up.status === 206 && maybeText && canBuffer) {
        try {
          if (up.body) await up.body.cancel();
        } catch {
          /* ignore */
        }
        const fwd2 = new Headers();
        for (const h of ['accept', 'accept-language', 'if-none-match', 'if-modified-since']) {
          const v = req.headers.get(h);
          if (v) fwd2.set(h, v);
        }
        fwd2.set('User-Agent', req.headers.get('User-Agent') || 'Mozilla/5.0 (compatible; TunerProxy/2.0)');
        fwd2.set('Accept-Encoding', 'identity');
        if (hop.authorization) fwd2.set('Authorization', hop.authorization);
        up = await fetch(hop.url, { method: 'GET', headers: fwd2, redirect: 'manual', signal: ac.signal });
        ct = (up.headers.get('content-type') || '').toLowerCase();
      }

      const resHeaders = new Headers();
      up.headers.forEach((v, k) => {
        if (!STRIP_HEADERS.has(k.toLowerCase())) resHeaders.set(k, v);
      });
      for (const [k, v] of Object.entries(cors)) resHeaders.set(k, v);

      if (req.method === 'GET' && maybeText && up.status !== 206 && up.status < 400 && canBuffer && up.body) {
        const buf = await readCapped(up.body, CONFIG.MAX_MANIFEST_BYTES);
        // readCapped locks + consumes the stream: when it bails out (over
        // cap) the body is unusable, so never fall through to up.body.
        if (!buf) {
          return new Response('Upstream response too large', { status: 502, headers: cors });
        }
        const text = new TextDecoder('utf-8').decode(buf);
        if (/^\uFEFF?#EXTM3U/.test(text)) {
          const selfBase = `${urlObj.origin}${urlObj.pathname}?url=`;
          const rewritten = rewriteManifest(text, finalUrl, selfBase);
          for (const k of ['content-length', 'content-encoding', 'etag', 'last-modified', 'expires', 'accept-ranges', 'content-range']) {
            resHeaders.delete(k);
          }
          resHeaders.set('content-type', 'application/vnd.apple.mpegurl');
          resHeaders.set('cache-control', 'no-store');
          return new Response(rewritten, { status: up.status, headers: resHeaders });
        }
        resHeaders.set('content-length', String(buf.byteLength));
        return new Response(buf, { status: up.status, headers: resHeaders });
      }

      return new Response(req.method === 'HEAD' ? null : up.body, { status: up.status, headers: resHeaders });
    } catch {
      return new Response('Upstream fetch failed', { status: 502, headers: cors });
    } finally {
      clearTimeout(killer);
    }
  },
};
