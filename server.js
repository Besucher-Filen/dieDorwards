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
    return req.socket?.remoteAddress || req.ip || '';
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
app.use(express.static(path.join(__dirname, 'public')));
app.use(checkRateLimit); // Rate-Limiter auf alle Anfragen anwenden

// === LOGIN ROUTE (ohne E-Mail) ===
app.post("/api/login", async (req, res) => {
    const { username } = req.body || {};
    console.log("Login-Anfrage von:", username);

    const allowedLower = loadAllowedUsers();
    if (!username || !allowedLower.includes(username.trim().toLowerCase())) {
        console.log("Unbekannter Benutzer / unknown username", username);

        // Sofortige Antwort → KEIN Warten
        res.status(401).json({ error: "Unbekannter Benutzername / unknown username" });

        // 🆕 NEU: Audit-Log (unauthorized)
        logLoginEvent({ username, result: 'unauthorized' }, req);
        return;
    }

    // Erfolgreich → JSON mit Link (sofort antworten)
    res.json({ filenLink: loadFilenLink() });

    // 🆕 NEU: Audit-Log (success)
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
        const csv = entries.map(e =>
            [e.ts, e.username ?? '', e.result, e.ip ?? '', (e.ua ?? '').replace(/"/g, '""')]
            .map(v => `"${v}"`).join(',')
        ).join('\n');
        res.set('Content-Type', 'text/csv');
        res.send(header + csv + '\n');
    });
});

// 🆕 NEU: Einfache Browser-Adminseite zum Ansehen & Exportieren der Audit-Logs
// Aufruf: https://diedorwards.onrender.com/admin/audit
app.get('/admin/audit', (req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Audit-Log</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 20px; }
  h1 { margin: 0 0 12px; font-size: 1.3rem; }
  .card { border: 1px solid #8883; border-radius: 12px; padding: 16px; margin-bottom: 16px; }
  label { display:block; font-size:.9rem; margin: 8px 0 4px; }
  input, button { padding: 8px 10px; border-radius: 8px; border: 1px solid #8885; }
  input[type="number"] { width: 120px; }
  button { cursor: pointer; }
  table { width:100%; border-collapse: collapse; margin-top: 12px; font-size: .95rem; }
  th, td { border-bottom: 1px solid #8883; padding: 8px; text-align: left; vertical-align: top; }
  th { position: sticky; top: 0; background: #fff; }
  .row { display:flex; gap:12px; align-items:center; flex-wrap: wrap; }
  .muted { color: #666; font-size: .85rem; }
  .ok { color: #0a0; }
  .err { color: #a00; }
  .badge { padding:2px 6px; border-radius:6px; font-size:.8rem; }
  .success { background:#0a02; border:1px solid #0a05; }
  .unauth { background:#a002; border:1px solid #a005; }
</style>
</head>
<body>
  <h1>Audit-Log (Admin)</h1>

  <div class="card">
    <div class="row">
      <div>
        <label for="token">Admin-Token</label>
        <input id="token" type="password" placeholder="ADMIN_TOKEN eingeben">
      </div>
      <div>
        <label for="limit">Anzahl Einträge</label>
        <input id="limit" type="number" min="1" max="1000" value="200">
      </div>
      <div style="align-self: end; display:flex; gap:8px; margin-bottom:4px;">
        <button id="btnSave">Token speichern</button>
        <button id="btnLoad">Laden</button>
        <button id="btnExport">CSV exportieren</button>
        <button id="btnClear">Token löschen</button>
      </div>
    </div>
    <div class="muted">Hinweis: Setze in Render eine Environment Variable <code>ADMIN_TOKEN</code>. Diese Seite sendet den Token als Header <code>x-admin-token</code> an <code>/api/audit</code>.</div>
    <div id="status" class="muted" style="margin-top:8px;"></div>
  </div>

  <div class="card" style="overflow:auto; max-height: 70vh;">
    <table id="tbl">
      <thead>
        <tr>
          <th>Zeit (UTC)</th>
          <th>Benutzername</th>
          <th>Ergebnis</th>
          <th>IP</th>
          <th>User-Agent</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  </div>

<script>
(function(){
  const $ = sel => document.querySelector(sel);

  const els = {
    token: $('#token'),
    limit: $('#limit'),
    status: $('#status'),
    tbody: document.querySelector('#tbl tbody'),
    btnSave: document.querySelector('#btnSave'),
    btnLoad: document.querySelector('#btnLoad'),
    btnExport: document.querySelector('#btnExport'),
    btnClear: document.querySelector('#btnClear'),
  };

  // LocalStorage-Helpers
  const KEY = 'audit_admin_token';
  function getToken(){ return localStorage.getItem(KEY) || ''; }
  function setToken(v){ localStorage.setItem(KEY, v||''); }
  function clearToken(){ localStorage.removeItem(KEY); }

  // Init
  els.token.value = getToken();

  function setStatus(msg, ok){
    els.status.textContent = msg || '';
    els.status.className = ok ? 'ok' : (ok===false ? 'err' : 'muted');
  }

  function renderRows(items){
    els.tbody.innerHTML = '';
    if (!items.length) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="5" class="muted">Keine Einträge.</td>';
      els.tbody.appendChild(tr);
      return;
    }
    for (const e of items) {
      const tr = document.createElement('tr');
      const resBadge = e.result === 'success'
        ? '<span class="badge success">success</span>'
        : '<span class="badge unauth">unauthorized</span>';
      tr.innerHTML = \`
        <td>\${e.ts || ''}</td>
        <td>\${(e.username ?? '').toString().replace(/</g,'&lt;')}</td>
        <td>\${resBadge}</td>
        <td>\${(e.ip ?? '')}</td>
        <td class="muted">\${(e.ua ?? '').toString().replace(/</g,'&lt;')}</td>\`;
      els.tbody.appendChild(tr);
    }
  }

  async function loadAudit(){
    const token = els.token.value.trim();
    if (!token) { setStatus('Bitte ADMIN_TOKEN eingeben.', false); return; }
    const limit = Math.max(1, Math.min(parseInt(els.limit.value||'200',10) || 200, 1000));
    setStatus('Lade ...');

    try {
      const res = await fetch(\`/api/audit?limit=\${limit}\`, {
        headers: { 'x-admin-token': token }
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(\`HTTP \${res.status}: \${t}\`);
      }
      const data = await res.json();
      renderRows(data);
      setStatus(\`\${data.length} Einträge geladen.\`, true);
    } catc
