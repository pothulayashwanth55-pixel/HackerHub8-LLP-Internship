# Pothula Yashwanth — Correct 2-Week Intern Projects
Student ID: HH8-9014638

## Project 1: Honeypot Login Page (`honeypot_login_page.py`)

A fake login page (Flask) that logs every login attempt — IP address,
username/password tried, and HTTP headers — to a local SQLite database.
It always shows "Invalid username or password," because there is no real
account behind it. It's a decoy, not a real auth system.

**Run it:**
```bash
pip install flask
python3 honeypot_login_page.py
```
Then visit:
- `http://127.0.0.1:5000/` — the fake login form
- `http://127.0.0.1:5000/admin/logs` — captured attempts

**Important (per your brief's tip):** this is intentionally **not** linked
to a real user database. Only run it on an isolated test VM/host — never
on a machine with real credentials or production data.

---

## Project 2: Secure Notes App (`secure_notes_app.py`)

An encrypted notes app. You supply a passphrase; a key is derived from it
with PBKDF2, then each note is encrypted with AES-GCM before it ever
touches disk. The file on disk only ever contains ciphertext.

**Run it:**
```bash
pip install cryptography
python3 secure_notes_app.py
```

The demo will:
1. Encrypt and save two notes.
2. Show you the raw file on disk (ciphertext only).
3. Decrypt with the correct passphrase.
4. Try decrypting with the wrong passphrase (fails safely).

**Per your brief's tip:** the AES key is derived fresh each time from the
passphrase and is explicitly wiped (overwritten with zeros) from memory
right after use — it's never written to disk and doesn't linger in RAM.

---

## Notes
Both scripts have a `demo()`/`if __name__ == "__main__"` entry point, so
you can just run them directly to see them work end-to-end.
