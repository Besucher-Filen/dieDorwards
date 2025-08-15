// server.js
const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
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

// === E-MAIL KONFIGURATION ===
const OWNER_EMAIL = "Besucher-filen@gmx.de"; // <== Deine eigene E-Mail-Adresse

const transporter = nodemailer.createTransport({
    host: "mail.gmx.net",
    port: 587,
    secure: false,
    auth: {
        user: OWNER_EMAIL,
        pass: process.env.GMX_PASS // Passwort aus Umgebungsvariable
    }
});

// === MIDDLEWARE ===
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(checkRateLimit); // Rate-Limiter auf alle Anfragen anwenden

// === LOGIN ROUTE ===
app.post("/api/login", async (req, res) => {
    const { username } = req.body || {};
    console.log("Login-Anfrage von:", username);

    const allowedLower = loadAllowedUsers();
    if (!username || !allowedLower.includes(username.trim().toLowerCase())) {
        console.log("Unbekannter Benutzer / unknown username", username);

        // E-Mail senden bei falschem Benutzernamen
        try {
            await transporter.sendMail({
                from: OWNER_EMAIL,
                to: OWNER_EMAIL,
                subject: `Unerlaubter Login-Versuch: ${username}`,
                text: `Jemand hat versucht, sich mit dem Benutzernamen '${username}' anzumelden.`
            });
            console.log("E-Mail für falschen Benutzer gesendet:", username);
        } catch (err) {
            console.error("E-Mail-Fehler bei falschem Benutzer:", err);
        }

        return res.status(401).json({ error: "Unbekannter Benutzername / unknown username" });
    }

    // E-Mail senden bei erfolgreichem Login
    try {
        await transporter.sendMail({
            from: OWNER_EMAIL,
            to: OWNER_EMAIL,
            subject: `${username} hat sich angemeldet`,
            text: `${username} hat sich angemeldet.`
        });
        console.log("E-Mail gesendet für", username);
    } catch (err) {
        console.error("E-Mail-Fehler:", err);
    }

    // Erfolgreich → JSON mit Link
    return res.json({ filenLink: loadFilenLink() });
});

// === SERVER START ===
app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));
