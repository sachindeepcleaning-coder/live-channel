#!/usr/bin/env node
/**
 * Builds the compact per-country data files served by the site.
 *
 * Source: the iptv-org/api repository (branch `gh-pages`) — the same files the
 * browser used to download on every load (streams/channels/feeds/logos).
 * Instead of pulling ~3 MB of JSON into the browser, this tool writes one
 * small file per country plus an index, so a page load costs a few tens of
 * kilobytes.
 *
 * Usage:
 *   node tools/build-data.mjs [--api <iptv-org/api clone>] [--out <dir>] [--epg <iptv-org/epg clone>]
 *
 * The api clone may be a working tree checked out on `gh-pages` or a normal
 * clone with the branch fetched (the tool falls back to `git show`).
 */

import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function arg(name, fallback) {
  const i = process.argv.indexOf('--' + name)
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback
}

const API_DIR = path.resolve(arg('api', path.join(ROOT, 'iptv', 'api')))
const OUT_DIR = path.resolve(arg('out', path.join(ROOT, 'data')))

const CAT_NAMES = {
  animation: 'Animation',
  auto: 'Auto',
  business: 'Business',
  classic: 'Classic',
  comedy: 'Comedy',
  cooking: 'Cooking',
  culture: 'Culture',
  documentary: 'Documentary',
  education: 'Education',
  entertainment: 'Entertainment',
  family: 'Family',
  general: 'General',
  interactive: 'Interactive',
  kids: 'Kids',
  legislative: 'Legislative',
  lifestyle: 'Lifestyle',
  movies: 'Movies',
  music: 'Music',
  news: 'News',
  outdoor: 'Outdoor',
  public: 'Public',
  relax: 'Relax',
  religious: 'Religious',
  series: 'Series',
  science: 'Science',
  shop: 'Shopping',
  sports: 'Sports',
  travel: 'Travel',
  weather: 'Weather',
  xxx: 'Adult'
}

/**
 * Public XMLTV guides that are reachable from a browser (CORS enabled) and
 * line up with iptv-org channel names or ids. `cors:false` means the file can
 * only be fetched through a proxy (Tuner's own worker/server or any CORS
 * proxy). The first entry of a country is the one loaded automatically.
 */
const EPG_GUIDES = [
  {
    id: 'tvepg-in',
    label: 'Indian channels (tvepg)',
    url: 'https://raw.githubusercontent.com/mitthu786/tvepg/main/epg.xml.gz',
    cors: true,
    countries: ['IN']
  },
  {
    id: 'jtbs-in',
    label: 'JTBS Classic (iptv-org worker)',
    url: 'https://jtbsclassic.dpdns.org/main.epg.xml',
    cors: true,
    countries: ['IN']
  },
  {
    id: 'epgtalk-uk',
    label: 'EPGTalk UK',
    url: 'https://raw.githubusercontent.com/acidjesuz/EPGTalk/master/UK_lite.xml.gz',
    cors: true,
    countries: ['UK']
  },
  {
    id: 'epgtalk-us',
    label: 'EPGTalk US free-to-air',
    url: 'https://raw.githubusercontent.com/acidjesuz/EPGTalk/master/FreeTV_guide.xml.gz',
    cors: true,
    countries: ['US']
  },
  {
    id: 'kanya-us',
    label: 'iptv-org US workers (exact channel ids — needs a proxy)',
    url: 'https://epg.kanya.io/us/guide.xml.gz',
    cors: false,
    countries: ['US']
  },
  {
    id: 'epgtalk-latino',
    label: 'EPGTalk Latino',
    url: 'https://raw.githubusercontent.com/acidjesuz/EPGTalk/master/Latino_lite.xml.gz',
    cors: true,
    countries: ['MX', 'AR', 'CL', 'CO', 'PE', 'VE', 'EC', 'BO', 'PY', 'UY']
  },
  {
    id: 'worker-fr',
    label: 'iptv-org FR workers',
    url: 'http://194.163.157.137:8080/iptv/epg.xml',
    cors: true,
    countries: ['FR']
  }
]

function readSource(file) {
  const local = path.join(API_DIR, file)
  if (fs.existsSync(local)) return JSON.parse(fs.readFileSync(local, 'utf8'))
  const out = execFileSync('git', ['-C', API_DIR, 'show', 'origin/gh-pages:' + file], {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 256
  })
  return JSON.parse(out)
}

function sourceDate() {
  try {
    return execFileSync('git', ['-C', API_DIR, 'log', '-1', '--format=%cI', 'origin/gh-pages'], {
      encoding: 'utf8'
    }).trim()
  } catch {
    return new Date().toISOString()
  }
}

function normHeaderValue(value, marker) {
  let s = String(value || '').trim()
  if (!s) return ''
  const i = s.indexOf(marker)
  if (i >= 0) s = s.slice(i + marker.length)
  else if (s.startsWith('#EXTVLCOPT:')) s = s.slice('#EXTVLCOPT:'.length)
  return s.replace(/[\r\n\0]/g, '').trim().slice(0, 250)
}

function main() {
  if (!fs.existsSync(API_DIR)) {
    console.error('iptv-org/api clone not found at ' + API_DIR)
    process.exit(1)
  }
  console.log('reading iptv-org/api …')
  const streams = readSource('streams.json')
  const channels = readSource('channels.json')
  const feeds = readSource('feeds.json')
  const logos = readSource('logos.json')
  const countries = readSource('countries.json')
  const updated = sourceDate().slice(0, 10)

  const chMap = new Map()
  for (const c of channels) chMap.set(c.id, c)
  const feedMap = new Map()
  for (const f of feeds) feedMap.set(f.channel + '|' + (f.id || ''), f)
  const logoFeed = new Map()
  const logoAny = new Map()
  for (const l of logos) {
    if (!l.channel || !l.url) continue
    if (l.feed) {
      const key = l.channel + '|' + l.feed
      if (l.in_use !== false || !logoFeed.has(key)) logoFeed.set(key, l.url)
    }
    if (!logoAny.has(l.channel)) logoAny.set(l.channel, l.url)
  }
  const countryNames = new Map()
  const countryFlags = new Map()
  for (const c of countries) {
    countryNames.set(c.code, c.name)
    countryFlags.set(c.code, c.flag || '')
  }

  const byCountry = new Map()
  const world = []
  let skipped = 0
  for (const s of streams) {
    const url = String(s.url || '')
    if (!/^https?:\/\//i.test(url)) {
      skipped++
      continue
    }
    const cid = s.channel || ''
    const meta = cid ? chMap.get(cid) : null
    const cc = meta && meta.country ? meta.country : ''
    if (!cc) continue
    const feed = cid && s.feed ? feedMap.get(cid + '|' + s.feed) : null
    const feedId = s.feed || ''
    const bits = []
    const feedName = feed && feed.name
    if (feedName && feedName !== 'SD' && feedName !== 'HD' && feedName !== 'FHD') bits.push(feedName)
    if (s.quality) bits.push(s.quality)
    let name = (meta && meta.name) || s.title || 'Channel'
    if (bits.length) name += ' (' + bits.join(' · ') + ')'
    let group = 'General'
    if (meta && meta.categories && meta.categories.length) {
      const cat = meta.categories[0]
      group = CAT_NAMES[cat] || cat.charAt(0).toUpperCase() + cat.slice(1)
    }
    const logo =
      (cid && feedId && logoFeed.get(cid + '|' + feedId)) || (cid ? logoAny.get(cid) : '') || ''
    const adult = Boolean(meta && meta.is_nsfw) || /\b(xxx|porn|playboy)\b|18\+/i.test(name)
    const entry = { n: name, u: url }
    if (s.quality) entry.q = s.quality
    if (feedId) entry.f = feedId
    if (logo) entry.l = logo
    if (group !== 'General') entry.g = group
    if (cid) entry.c = cid
    if (adult) entry.x = 1
    if (s.labels && s.labels.length) entry.b = s.labels
    const ref = normHeaderValue(s.referrer, 'http-referrer=')
    if (ref) entry.r = ref
    const ua = normHeaderValue(s.user_agent, 'http-user-agent=')
    if (ua) entry.a = ua
    if (!byCountry.has(cc)) byCountry.set(cc, [])
    byCountry.get(cc).push(entry)
    world.push(entry)
  }

  fs.writeFileSync(
    path.join(OUT_DIR, 'world.json'),
    JSON.stringify({ v: 1, updated, country: 'world', streams: world })
  )

  fs.mkdirSync(OUT_DIR, { recursive: true })
  const index = []
  let total = 0
  for (const [cc, list] of [...byCountry.entries()].sort()) {
    const file = cc.toLowerCase() + '.json'
    const payload = { v: 1, updated, country: cc, streams: list }
    fs.writeFileSync(path.join(OUT_DIR, file), JSON.stringify(payload))
    const channelsInCountry = new Set(list.map(e => e.c).filter(Boolean)).size
    index.push({
      code: cc,
      name: countryNames.get(cc) || cc,
      flag: countryFlags.get(cc) || '',
      streams: list.length,
      channels: channelsInCountry,
      file
    })
    total += list.length
  }

  fs.writeFileSync(
    path.join(OUT_DIR, 'index.json'),
    JSON.stringify({ v: 1, updated, countries: index, streams: total })
  )

  const epg = { v: 1, updated, guides: EPG_GUIDES }
  fs.writeFileSync(path.join(OUT_DIR, 'epg.json'), JSON.stringify(epg, null, 1))

  const bytes = index.reduce((n, c) => n + fs.statSync(path.join(OUT_DIR, c.file)).size, 0)
  console.log(
    'wrote ' + index.length + ' country files (' + index.length + ' countries, ' + total + ' streams, ' + Math.round(bytes / 1024) + ' KB total)'
  )
  console.log('skipped ' + skipped + ' non-http streams')
  console.log('updated ' + updated)
}

main()
