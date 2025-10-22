// server.js
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000; // Render nutzt process.env.PORT

// ====== Dateien laden ======
function loadAllowedUsers() {
  try {
    const data = fs.readFileSync(path.join(__dirname, 'users.json'), 'utf8');
    return JSON.parse(data).map(u => u.toLowerCase());
  } catch (err) {
    console.error('Fehler beim Laden von users.json:', err);
    return [];
  }
}
function loadFilenLink() {
  try {
    return fs.readFileSync(path.join(__dirname, 'filenlink.txt'), 'utf8').trim();
  } catch (err) {
    console.error('Fehler beim Laden von filenlink.txt:', err);
    return '';
  }
}

// ====== Einfacher Monats-Rate-Limiter ======
const RATE_LIMIT = 10000; // Max. Anfragen pro Monat (global)
let requestCounts = 0;
const resetTime = new Date();
resetTime.setMonth(resetTime.getMonth() + 1);
resetTime.setDate(1);
resetTime.setHours(0, 0, 0, 0);

// Health-Checks vom Limit ausnehmen, sonst 429 bei /healthz
function checkRateLimit(req, res, next) {
  if (req.path === '/healthz' || req.path === '/') return next();

  const now = new Date();
  if (now >= resetTime) {
    requestCounts = 0;
    resetTime.setMonth(now.getMonth() + 1);
    resetTime.setDate(1);
    resetTime.setHours(0, 0, 0, 0);
  }

  if (requestCounts >= RATE_LIMIT) {
    return res.status(429).json({ error: 'Rate limit exceeded. Try next month.' });
  }
  requestCounts++;
  next();
}

// ====== ENV (in Render setzen) ======
const ADMIN_TOKEN = process.env.ADMIN_TOKEN; // Pflicht für Admin-API
const UP_URL   = process.env.UPSTASH_REDIS_REST_URL;   // https://...upstash.io (REST URL)
const UP_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN; // WRITE-Token (nicht read-only)

if (!UP_URL || !UP_TOKEN) {
  console.warn('⚠️  Upstash ENV fehlt: UPSTASH_REDIS_REST_URL oder UPSTASH_REDIS_REST_TOKEN ist nicht gesetzt.');
}
if (!ADMIN_TOKEN) {
  console.warn('⚠️  ADMIN_TOKEN ist nicht gesetzt. /api/audit-Endpunkte werden 401 liefern.');
}

// ====== Helpers ======
function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (xf) return xf.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || req.ip || '';
}
async function fetchWithTimeout(url, opts = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
}

// ====== Upstash: Schreiben (LPUSH + LTRIM via /pipeline) ======
async function upstashAppendAudit(entryObj) {
  if (!UP_URL || !UP_TOKEN) {
    console.warn('Upstash ENV fehlt: UPSTASH_REDIS_REST_URL / _TOKEN');
    return false;
  }
  try {
    const payload = [
      ['LPUSH', 'audit:logins', JSON.stringify(entryObj)],
      ['LTRIM', 'audit:logins', 0, 4999] // max. 5000 Einträge
    ];
    const res = await fetchWithTimeout(UP_URL + '/pipeline', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${UP_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    }, 8000);

    let data = null, text = '';
    try { data = await res.json(); } catch { text = await res.text().catch(()=>''); }

    if (!res.ok) {
      console.error('Upstash pipeline HTTP-Fehler:', res.status, data || text);
      return false;
    }
    if (!Array.isArray(data)) {
      console.error('Upstash pipeline: Unerwartete Antwort:', data);
      return false;
    }
    const errItem = data.find(d => d && d.error);
    if (errItem) {
      console.error('Upstash pipeline command error:', errItem.error, data);
      return false;
    }
    return true;
  } catch (err) {
    console.error('Upstash pipeline Exception:', err && err.message ? err.message : err);
    return false;
  }
}

// ====== Upstash: Lesen (LRANGE) ======
async function upstashFetchAudit(limit) {
  if (!UP_URL || !UP_TOKEN) return [];
  try {
    const end = Math.max(0, limit - 1);
    const res = await fetchWithTimeout(UP_URL + '/lrange/audit:logins/0/' + end, {
      headers: { 'Authorization': `Bearer ${UP_TOKEN}` }
    }, 8000);

    let data = null, text = '';
    try { data = await res.json(); } catch { text = await res.text().catch(()=>''); }

    if (!res.ok) {
      console.error('Upstash LRANGE HTTP-Fehler:', res.status, data || text);
      return [];
    }
    if (!data || (!Array.isArray(data.result) && data.error)) {
      console.error('Upstash LRANGE Fehler:', data && data.error ? data.error : (data || text));
      return [];
    }
    if (!Array.isArray(data.result)) return [];

    // LPUSH speichert neuestes zuerst → für Anzeige umdrehen
    const parsed = data.result.map(s => {
      try { return JSON.parse(s); } catch { return null; }
    }).filter(Boolean);
    return parsed.reverse();
  } catch (err) {
    console.error('Upstash Fetch Exception:', err && err.message ? err.message : err);
    return [];
  }
}

// ====== Admin-Check ======
function ensureAdmin(req, res) {
  if (!ADMIN_TOKEN) {
    res.status(500).json({ error: 'ADMIN_TOKEN ist nicht gesetzt (Environment Variable).' });
    return false;
  }
  const tok = req.get('x-admin-token');
  if (tok !== ADMIN_TOKEN) {
    res.status(401).json({ error: 'unauthorized' });
    return false;
  }
  return true;
}

// ====== Middleware ======
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Health-Checks (vor Limiter, zusätzlich zum Skip in checkRateLimit)
app.get('/', (req, res) => {
  res.type('text/plain').send('OK');
});
app.get('/healthz', (req, res) => {
  res.status(200).json({ ok: true, time: new Date().toISOString() });
});

// Limiter NACH Health-Routen
app.use(checkRateLimit);

// Alias /login -> /api/login (Kompatibilität fürs Frontend)
app.post('/login', (req, res, next) => {
  req.url = '/api/login';
  next();
});

// ====== LOGIN (ohne E-Mail, mit Upstash-Audit) ======
app.post('/api/login', async (req, res) => {
  const username = (req.body && req.body.username) || '';
  console.log('Login-Anfrage von:', username);

  const allowedLower = loadAllowedUsers();
  if (!username || !allowedLower.includes(username.trim().toLowerCase())) {
    console.log('Unbekannter Benutzer / unknown username', username);

    // Sofortige Antwort → KEIN Warten
    res.status(401).json({ error: 'Unbekannter Benutzername / unknown username' });

    // Audit (unauthorized)
    const entry = {
      ts: new Date().toISOString(),
      username: username || null,
      result: 'unauthorized',
      ip: getClientIp(req),
      ua: req.get('user-agent') || null
    };
    console.log('[AUDIT]', JSON.stringify(entry));
    upstashAppendAudit(entry); // asynchron
    return;
  }

  // Erfolgreich → JSON mit Link (sofort)
  res.json({ filenLink: loadFilenLink() });

  // Audit (success)
  const entry = {
    ts: new Date().toISOString(),
    username: username,
    result: 'success',
    ip: getClientIp(req),
    ua: req.get('user-agent') || null
  };
  console.log('[AUDIT]', JSON.stringify(entry));
  upstashAppendAudit(entry); // asynchron
});

// ====== Admin-API ======
app.get('/api/audit', async (req, res) => {
  if (!ensureAdmin(req, res)) return;
  const limit = Math.max(1, Math.min(Number(req.query.limit) || 100, 1000));
  const rows = await upstashFetchAudit(limit);
  res.json(rows);
});

app.get('/api/audit.csv', async (req, res) => {
  if (!ensureAdmin(req, res)) return;
  const limit = Math.max(1, Math.min(Number(req.query.limit) || 1000, 5000));
  const entries = await upstashFetchAudit(limit);
  const header = 'ts,username,result,ip,ua\n';
  const csv = entries.map(e => {
    const vals = [
      e.ts,
      e.username || '',
      e.result,
      e.ip || '',
      String(e.ua || '').replace(/"/g, '""')
    ];
    return vals.map(v => '"' + String(v) + '"').join(',');
  }).join('\n');
  res.set('Content-Type', 'text/csv');
  res.send(header + csv + '\n');
});

// Selftest (Write + Read prüfen)
app.get('/api/audit-selftest', async (req, res) => {
  if (!ensureAdmin(req, res)) return;
  const testEntry = {
    ts: new Date().toISOString(),
    username: '__selftest__',
    result: 'success',
    ip: '127.0.0.1',
    ua: 'selftest'
  };
  const writeOk = await upstashAppendAudit(testEntry);
  const last = await upstashFetchAudit(5);
  const sawSelf = last.some(e => e.username === '__selftest__');
  res.json({
    envOk: Boolean(UP_URL && UP_TOKEN),
    writeOk,
    readOk: last.length >= 1,
    sawSelftest: sawSelf,
    lastCount: last.length,
    last
  });
});

// ====== Admin-Seite (statisch) ======
app.get('/admin/audit', (req, res) => {
  res.redirect('/admin-audit.html');
});

// ====== Start ======
app.listen(PORT, () => console.log('Server läuft auf Port ' + PORT));
