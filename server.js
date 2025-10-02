// server.js
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000; // ✅ Render nutzt process.env.PORT

// === KONFIGURATION ===
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

// === RATE-LIMITER (einfach) ===
const RATE_LIMIT = 10000; // Max. Anfragen pro Monat
let requestCounts = 0;
const resetTime = new Date();
resetTime.setMonth(resetTime.getMonth() + 1);
resetTime.setDate(1);
resetTime.setHours(0, 0, 0, 0);

function checkRateLimit(req, res, next) {
  const now = new Date();
  if (now >= resetTime) {
    requestCounts = 0; // Reset monatlich
    resetTime.setMonth(now.getMonth() + 1);
    resetTime.setDate(1);
  }
  if (requestCounts >= RATE_LIMIT) {
    return res.status(429).json({ error: 'Rate limit exceeded. Try next month.' });
  }
  requestCounts++;
  next();
}

// === 🆕 NEU: Upstash Redis (REST) ===
// 🚨 ZU SETZEN in Render: ADMIN_TOKEN, UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
const ADMIN_TOKEN = process.env.ADMIN_TOKEN; // Pflicht für Admin-API
const UP_URL = process.env.UPSTASH_REDIS_REST_URL;   // z.B. https://eu1-xxxxx.upstash.io
const UP_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

if (!UP_URL || !UP_TOKEN) {
  console.warn('⚠️  Upstash ENV fehlt: UPSTASH_REDIS_REST_URL oder UPSTASH_REDIS_REST_TOKEN ist nicht gesetzt.');
}
if (!ADMIN_TOKEN) {
  console.warn('⚠️  ADMIN_TOKEN ist nicht gesetzt. /api/audit-Endpunkte werden 401 liefern.');
}

// Helfer: IP ermitteln
function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (xf) return xf.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || req.ip || '';
}

// 🆕 NEU: In Upstash schreiben (LPUSH + LTRIM via /pipeline)
async function upstashAppendAudit(entryObj) {
  if (!UP_URL || !UP_TOKEN) return;
  try {
    const payload = [
      ['LPUSH', 'audit:logins', JSON.stringify(entryObj)],
      ['LTRIM', 'audit:logins', 0, 4999] // auf max. 5000 Einträge begrenzen
    ];
    const res = await fetch(UP_URL + '/pipeline', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + UP_TOKEN,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
    // Erwartete Antwort: Array von Objekten mit { result: ... } (oder { error: ... })
    // Wir ignorieren hier bewusst die Details, loggen nur Fehlertext.
    if (!res.ok) {
      const t = await res.text();
      console.error('Upstash pipeline HTTP-Fehler:', res.status, t);
    }
  } catch (err) {
    console.error('Upstash pipeline Fehler:', err);
  }
}

// 🆕 NEU: Letzte N Einträge lesen (LRANGE)
async function upstashFetchAudit(limit) {
  if (!UP_URL || !UP_TOKEN) return [];
  try {
    const end = Math.max(0, limit - 1);
    const res = await fetch(UP_URL + '/lrange/audit:logins/0/' + end, {
      headers: { 'Authorization': 'Bearer ' + UP_TOKEN }
    });
    const data = await res.json(); // { result: [ 'json', 'json', ... ] } oder { error: '...' }
    if (data && Array.isArray(data.result)) {
      // LPUSH ⇒ Index 0 ist neuester; für Anzeige aufsteigend sortieren:
      const parsed = data.result.map(s => {
        try { return JSON.parse(s); } catch { return null; }
      }).filter(Boolean);
      return parsed.reverse();
    } else if (data && data.error) {
      console.error('Upstash LRANGE Fehler:', data.error);
      return [];
    }
  } catch (err) {
    console.error('Upstash Fetch Fehler:', err);
  }
  return [];
}

// 🆕 NEU: Admin-Check
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

// === MIDDLEWARE ===
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public'))); // bedient /public
app.use(checkRateLimit);

// === LOGIN ROUTE (ohne E-Mail, mit Upstash-Audit) ===
app.post('/api/login', async (req, res) => {
  const username = (req.body && req.body.username) || '';
  console.log('Login-Anfrage von:', username);

  const allowedLower = loadAllowedUsers();
  if (!username || !allowedLower.includes(username.trim().toLowerCase())) {
    console.log('Unbekannter Benutzer / unknown username', username);

    // Sofortige Antwort → KEIN Warten
    res.status(401).json({ error: 'Unbekannter Benutzername / unknown username' });

    // Audit-Log (unauthorized)
    const entry = {
      ts: new Date().toISOString(),
      username: username || null,
      result: 'unauthorized',
      ip: getClientIp(req),
      ua: req.get('user-agent') || null
    };
    console.log('[AUDIT]', JSON.stringify(entry)); // zusätzlich ins Log
    upstashAppendAudit(entry); // asynchron
    return;
  }

  // Erfolgreich → JSON mit Link (sofort antworten)
  res.json({ filenLink: loadFilenLink() });

  // Audit-Log (success)
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

// === AUDIT-API (JSON) – letzte N Einträge (default 100)
app.get('/api/audit', async (req, res) => {
  if (!ensureAdmin(req, res)) return;
  const limit = Math.max(1, Math.min(Number(req.query.limit) || 100, 1000));
  const rows = await upstashFetchAudit(limit);
  res.json(rows);
});

// === AUDIT-Export (CSV)
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

// === Admin-Seite als statische Datei (falls vorhanden)
// Aufruf: https://diedorwards.onrender.com/admin/audit  → leitet auf /admin-audit.html
app.get('/admin/audit', (req, res) => {
  res.redirect('/admin-audit.html');
});

// === SERVER START ===
app.listen(PORT, () => console.log('Server läuft auf Port ' + PORT));
