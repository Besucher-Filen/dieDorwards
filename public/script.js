document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("loginForm");
  const usernameInput = document.getElementById("username");
  const msgEl = document.getElementById("message");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = usernameInput.value.trim();
    msgEl.textContent = "";

    if (!username) {
      msgEl.textContent = "Bitte Benutzernamen eingeben.";
      return;
    }

    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username })
      });
      const data = await res.json().catch(() => null);

      if (!res.ok) {
        msgEl.textContent = (data && data.error) ? data.error : ("Fehler: " + res.status);
        return;
      }

      window.location.href = data.filenLink;
    } catch (err) {
      console.error("Fetch error:", err);
      msgEl.textContent = "Server nicht erreichbar.";
    }
  });
});
