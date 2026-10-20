/* Tuner offline shell v4 — network-first navigations, stale-while-revalidate
   for the precached shell only. Playlists, EPG, manifests, segments and
   anything cross-origin always go straight to the network.
   Shell paths are resolved against the worker's own base URL so the cache
   actually serves them under any base path (e.g. /live-channel/). */
const CACHE = 'tuner-shell-v7';
const BASE = new URL('./', self.location.href);
const SHELL = [
  './',
  './index.html',
  './manifest.webmanifest',
  './icon.svg',
  './icon-192.png',
  './icon-512.png',
  './hls.min.js',
  './qrcode.js',
].map((p) => new URL(p, BASE).href);
const SHELL_PATHS = new Set(SHELL.map((u) => new URL(u).pathname));

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches
      .open(CACHE)
      .then((c) => Promise.all(SHELL.map((u) => c.add(u).catch(() => {}))))
      .then(() => self.skipWaiting())
      .catch(() => {})
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

const INDEX_KEY = new Request(new URL('./index.html', self.location.href), { cache: 'reload' });

function isShell(u) {
  return SHELL_PATHS.has(u.pathname) || u.pathname.endsWith('/index.html');
}

async function networkFirst(req) {
  try {
    const r = await fetch(req);
    if (r && r.ok && r.type === 'basic' && !r.redirected) {
      const copy = r.clone();
      caches.open(CACHE).then((c) => c.put(INDEX_KEY, copy)).catch(() => {});
    }
    return r;
  } catch (err) {
    const hit = await caches.match(INDEX_KEY, { ignoreSearch: true });
    const root = hit || (await caches.match('./', { ignoreSearch: true }));
    return root || Response.error();
  }
}

async function staleWhileRevalidate(req) {
  const cache = await caches.open(CACHE);
  const cached = await cache.match(req, { ignoreSearch: true });
  const net = fetch(req)
    .then((r) => {
      if (r && r.status === 200 && r.type === 'basic' && !r.redirected) {
        const copy = r.clone();
        cache.put(req, copy).catch(() => {});
      }
      return r;
    })
    .catch(() => cached);
  return cached || net;
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET' || req.headers.get('Range')) return;
  const u = new URL(req.url);
  if (u.origin !== self.location.origin) return;
  if (req.mode === 'navigate') {
    e.respondWith(networkFirst(req));
    return;
  }
  if (!isShell(u)) return;
  e.respondWith(staleWhileRevalidate(req));
});
