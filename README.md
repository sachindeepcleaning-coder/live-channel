# Tuner

A single-file live IPTV player: vanilla HTML/JS + hls.js, no build step. Ships with a
Node CORS proxy (`server.js`), a Cloudflare Worker proxy (`worker.js`), a PWA service
worker, and a tiny Android WebView app (`android/`).

## Quick start

```bash
# 1. static server for the app
python3 -m http.server 8000

# 2. proxy + phone-remote server (Node 18+)
ALLOW_LOCAL=1 node server.js
```

Open <http://127.0.0.1:8000/index.html>. In Setup choose a playlist (India loads by
default), or open a local `.m3u`. The proxy is optional — it unlocks geo-blocked/CORS
streams when pointed at a VPS in the right country.

## Only-working filter (no proxy)

Tuner checks every channel for you and can hide the ones that need a proxy or are dead.

- The check runs automatically when a playlist loads: each stream URL is fetched
  **straight from the browser** (manifest → variant → first segment), so CORS, TLS,
  geo-blocks and dead files are detected. No proxy is involved in the test.
- The home screen shows a status bar: `61 of 67 channels play without a proxy`.
- **✔ Only working** (on the same bar, and in *Sources & proxy*) hides every channel
  that did not pass the check — the list then contains only streams that play directly.
- **Check again** re-tests everything; **Stop** halts a running check.
- Results are cached in `localStorage` (`iptv_scan_v1`): working channels stay known
  for 7 days, failures are retried after 24 hours, so the list is ready instantly on
  the next visit.
- Channels you play successfully are also marked as working, and a direct-play failure
  un-marks the channel immediately.

## iptv-org data sources

Two ways to get the same channels, both from [iptv-org](https://github.com/iptv-org):

- **.m3u playlist** (default) — `https://iptv-org.github.io/iptv/countries/in.m3u`,
  one entry per channel with the best available link.
- **JSON API** — *Sources & proxy → iptv-org API → Load JSON*. Downloads
  `streams.json`, `channels.json`, `logos.json` and `feeds.json` from
  `https://iptv-org.github.io/api/` (~3 MB compressed) and keeps **every** stream,
  not just the best one per channel. It adds data the .m3u does not carry:
  - `quality` (720p/1080p…) and the feed name in the channel title,
  - `is_nsfw` from the database, used for the adult filter,
  - `Geo-blocked` / `Not 24/7` labels (shown as ⚠ on the card),
  - country and category (used for the group chips),
  - logos per channel/feed,
  - the `Referer` and `User-Agent` some providers require.

Those last two are sent to Tuner's own proxy (`server.js`) or a deployed
`worker.js` as `?referer=…&ua=…` when a stream is played through it, so
providers that reject requests without them can still work. Browsers cannot
set those headers themselves, which is why such streams fail when played
directly. The values are sanitised (no CR/LF) before being forwarded.

## CRT Mode

Nostalgia mode: TV bezel, scanlines, film grain, vignette, and an analog zap on
channel change — plus a full old-TV front panel.

- Toggle: **📺 CRT Mode** on the watch screen, the **C** key, or `CRT off` in the panel.
- Front panel (overlays the bottom of the picture on desktop, sits below it on phones):
  **CH − / CH +** tune channels, **Channels** opens a retro channel guide,
  **Vol − / Vol + / Mute** control sound, **Info** shows channel + guide details (`I` key),
  **Share**, **Fullscreen**, **Remote** (phone pairing), **Power**, **CRT off**.
- On-screen display: tuning shows `CH 003` + channel name; volume/mute show `VOL 65%` / `MUTE`.
- A persistent channel banner (chyron) stays at the top of the picture, like a real TV.
- The native seek bar and normal action bar are hidden while CRT Mode is on.
- The preference is saved in `localStorage` (`tuner_crt`).
- `prefers-reduced-motion: reduce` keeps the static scanlines but disables the zap
  animation (CSS + JS both respect it).

## Phone remote

Turn your phone into the TV remote. Video and sound stay on the desktop.

1. Start the remote server on the computer showing the TV:
   `node server.js` (port 8080; use `PORT=... node server.js` to change).
2. Open Tuner on that computer and play a channel.
3. Click **📱 Remote** (watch screen or menu). A QR code and an 8-character code appear.
4. Scan the QR, or open the shown link on the phone and type the code.

The phone page has CH ▲/▼, VOL +/−, Mute and Power. The TV reports its current
channel, volume and playing state back to the phone.

Notes:

- Pairing codes expire after **5 minutes** (new code button regenerates), and only
  **one phone** can attach per TV.
- If the phone can't reach the TV, allow port 8080 through the computer firewall and
  make sure both devices are on the same Wi-Fi.
- On an HTTPS page (GitHub Pages) the browser blocks `ws://`; run Tuner locally, or
  put `server.js` behind TLS and enter a `wss://.../remote-ws` URL in the remote panel.
- `http://<tv>:8080/remote` and `index.html?remote=1` both open the phone page.
- Sessions are in memory (v1); restarting `server.js` drops the pairing. The remote
  works with `server.js` only — `worker.js` is proxy-only.

## Android APK

The site links to `Tuner-v2.2.1.apk` (built from `android/`, release-signed with
v1+v2 schemes, minSdk 21). If installation fails:

1. Allow **Install unknown apps** for the browser/file manager you downloaded with.
2. Delete a previously installed Tuner if the package conflicts
   (`adb uninstall com.tuner.app`).
3. Install from the notification or a file manager rather than an in-browser viewer.
4. Rebuild with `cd android && ./gradlew assembleRelease` (needs JDK 17 + Android SDK 34;
   the Gradle wrapper is committed, so no global Gradle install is needed). Signing
   credentials live in `android/keystore.properties`, kept out of git — restore it and
   `android/keystore/tuner-release.jks` from your backup, future updates need the same key
   or users cannot update in place. Without them the release build fails fast with an
   explanatory error; `./gradlew assembleDebug` builds a debuggable APK for testing.
