
// server.js
const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// === KONFIGURATION ===
const ALLOWED_USERS = ["Katja", "peter", "lisa"]; // Erlaubte Benutzernamen
const FILEN_LINK = "https://app.filen.io/#/drive/af477eeb-10ca-4e10-b3d2-5f588a346bc5/4e5d9965-353b-4381-870b-cd20077bfe0f"; // <== Hier monatlich den aktuellen filen.io-Link eintragen
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

    const allowedLower = ALLOWED_USERS.map(u => u.toLowerCase());
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
    return res.json({ filenLink: FILEN_LINK });
});

app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));
