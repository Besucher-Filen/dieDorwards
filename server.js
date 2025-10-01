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
    console.error("Fehler beim Laden von users.json:", err);
    return [];
  }
}

function loadFilenLink() {
  try {
    return fs.readFileSync(path.join(__dirname, 'filenlink.txt'), 'utf8').trim();
  } catch (err) {
    console.error("Fehler beim Laden von filenlink.txt:", err);
    return "";
  }
}

// === RATE-LIMITER ===
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
    return res.status(429).json({ error: "Rate limit exceeded. Try next month." });
  }
  requestCounts++;
  next();
}

// 🆕 NEU: Audit-Logging (statt E-Mail)
const AUDIT_FILE = path.join(__dirname, 'audit.jsonl'); // eine JSON-Zeile pro Event
const ADMIN_TOKEN = process.env.ADMIN_TOKEN; // 🚨 ZU SETZEN: in Render als Environment Variable hinterlegen

function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (xf) return xf.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || req.ip || '';
}

function logLoginEvent({ username, result }, req) {
  const entry = {
    ts: new Date().toISOString(),
    username: username || null,
    result, // 'success' | 'unauthorized'
    ip: getClientIp(req),
    ua: req.get('user-agent') || null
  };
  fs.appendFile(AUDIT_FILE, JSON.stringify(entry) + '\n', (err) => {
    if (err) console.error('Audit-Log Fehler:', err);
  });
}

// 🆕 NEU: sehr einfacher Admin-Check für Audit-Endpunkte
function ensureAdmin(req, res) {
  if (!ADMIN_TOKEN) {
    res.status(500).json({ error: "ADMIN_TOKEN ist nicht gesetzt (Environment Variable)." });
    return false;
  }
  const tok = req.get('x-admin-token');
  if (tok !== ADMIN_TOKEN) {
    res.status(401).json({ error: "unauthorized" });
    return false;
  }
  return true;
}

// === MIDDLEWARE ===
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public'))); // bedient /public
app.use(checkRateLimit);

// === LOGIN ROUTE (ohne E-Mail) ===
app.post("/api/login", async (req, res) => {
  const { username } = req.body || {};
  console.log("Login-Anfrage von:", username);

  const allowedLower = loadAllowedUsers();
  if (!username || !allowedLower.includes(username.trim().toLowerCase())) {
    console.log("Unbekannter Benutzer / unknown username", username);

    // Sofortige Antwort → KEIN Warten
    res.status(401).json({ error: "Unbekannter Benutzername / unknown username" });

    // Audit-Log (unauthorized)
    logLoginEvent({ username, result: 'unauthorized' }, req);
    return;
  }

  // Erfolgreich → JSON mit Link (sofort antworten)
  res.json({ filenLink: loadFilenLink() });

  // Audit-Log (success)
  logLoginEvent({ username, result: 'success' }, req);
});

// 🆕 NEU: Audit-API (JSON) – letzte N Einträge (default 100)
app.get('/api/audit', (req, res) => {
  if (!ensureAdmin(req, res)) return;
  fs.readFile(AUDIT_FILE, 'utf8', (err, data = '') => {
    if (err) {
      if (err.code === 'ENOENT') return res.json([]);
      return res.status(500).json({ error: 'read error' });
    }
    const lines = data.trim() ? data.trim().split('\n') : [];
    const entries = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    const limit = Math.max(1, Math.min(Number(req.query.limit) || 100, 1000));
    res.json(entries.slice(-limit));
  });
});

// 🆕 NEU: Audit-Export (CSV)
app.get('/api/audit.csv', (req, res) => {
  if (!ensureAdmin(req, res)) return;
  fs.readFile(AUDIT_FILE, 'utf8', (err, data = '') => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.set('Content-Type', 'text/csv');
        return res.send('ts,username,result,ip,ua\n');
      }
      return res.status(500).json({ error: 'read error' });
    }
    const lines = data.trim() ? data.trim().split('\n') : [];
    const entries = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    const header = 'ts,username,result,ip,ua\n';
    const csv = entries.map(e => {
      const vals = [
        e.ts,
        e.username || '',
        e.result,
        e.ip || '',
        (e.ua || '').replace(/"/g, '""')
      ];
      return vals.map(v => '"' + String(v) + '"').join(',');
    }).join('\n');
    res.set('Content-Type', 'text/csv');
    res.send(header + csv + '\n');
  });
});

// 🆕 NEU: Admin-Seite als statische Datei aus /public
// Aufruf: https://diedorwards.onrender.com/admin/audit
app.get('/admin/audit', (req, res) => {
  // leitet auf die statische HTML-Datei um (siehe Schritt 2 unten)
  res.redirect('/admin-audit.html');
});

// === SERVER START ===
app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));
