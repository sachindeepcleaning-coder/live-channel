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
