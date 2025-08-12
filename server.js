
// server.js
const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

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
const OWNER_EMAIL = "Besucher-filen@gmx.de"; // <== Deine eigene E-Mail-Adresse

// SMTP-Einstellungen für GMX
const transporter = nodemailer.createTransport({
    host: "mail.gmx.net",
    port: 587,
    secure: false,
    auth: {
        user: "Besucher-filen@gmx.de", // GMX Login (meist E-Mail-Adresse)
        pass: "BesucherFilen" // GMX Passwort
    }
});

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post("/api/login", async (req, res) => {
    const { username } = req.body || {};
    console.log("Login-Anfrage von:", username);

    const allowedLower = loadAllowedUsers();  // neue Funktion, die users.json liest
    if (!username || !allowedLower.includes(username.trim().toLowerCase())) {
        console.log("Unbekannter Benutzer:", username);
        return res.status(401).json({ error: "Unbekannter Benutzername" });
    }


    // E-Mail senden
    try {
        await transporter.sendMail({
            from: OWNER_EMAIL,
            to: OWNER_EMAIL,
            subject: `Fotozugang: ${username}`,
            text: `${username} hat sich angemeldet.`
        });
        console.log("E-Mail gesendet für", username);
    } catch (err) {
        console.error("E-Mail-Fehler:", err);
    }

    // Erfolgreich → JSON mit Link
    return res.json({ filenLink: loadFilenLink() });
});

app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));
