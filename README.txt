ANLEITUNG - FOTOZUGANG

1. Voraussetzungen:
   - Node.js installiert (https://nodejs.org/)
   - GMX-E-Mail-Adresse + Passwort

2. Einmalige Einrichtung:
   - ZIP entpacken
   - In 'server.js' folgende Stellen anpassen:
       const ALLOWED_USERS = ["anna", "peter", "lisa"]; // Erlaubte Benutzernamen
       const FILEN_LINK = "HIER_DEIN_FILEN_LINK";       // Monatlich anpassen
       const OWNER_EMAIL = "DEINE_EMAIL@BEISPIEL.DE";  // Deine E-Mail
       auth: { user: "DEIN_GMX_LOGIN", pass: "DEIN_GMX_PASSWORT" }
   - Speichern

3. Starten (im Projektordner):
     node server.js

4. Aufruf im Browser:
     http://localhost:3000

5. Monatlich:
   - 'server.js' öffnen
   - FILEN_LINK auf den neuen filen.io-Link setzen
   - Server neu starten

6. Hinweis:
   - Die Besucher sehen nur die Login-Maske.
   - Bei erfolgreicher Anmeldung wirst du per E-Mail benachrichtigt.
   - Danach werden sie zu deinem filen.io-Link weitergeleitet.
