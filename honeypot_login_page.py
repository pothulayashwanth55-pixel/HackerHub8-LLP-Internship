"""
Honeypot Login Page
=====================
Project 1 - Deception technology.

A fake login page that looks real but is NOT connected to any real user
database. Its only purpose is to lure attackers/bots and log everything
about their attempt: source IP, the credentials they tried, and their
HTTP headers (User-Agent, etc.) — useful for threat intelligence.

Tools: Flask, SQLite

How it works:
    - Serves a normal-looking login form.
    - No matter what is entered, the login always "fails" (there is no
      real backend to succeed against).
    - Every attempt (IP, username, password, headers, timestamp) is logged
      to a local SQLite database for later analysis.

Tips implemented:
    - This is a DECOY only — it is deliberately NOT linked to any real
      user database or real authentication system.
    - Run this only on an isolated test host/VM, never on a machine with
      real credentials or production data.
"""

import sqlite3
from datetime import datetime
from pathlib import Path

from flask import Flask, request, render_template_string

DB_PATH = Path(__file__).parent / "honeypot_log.db"

app = Flask(__name__)

LOGIN_PAGE = """
<!doctype html>
<html>
<head><title>Employee Portal Login</title></head>
<body style="font-family: Arial; max-width: 320px; margin: 80px auto;">
    <h2>Employee Portal</h2>
    <form method="POST" action="/login">
        <label>Username:</label><br>
        <input type="text" name="username"><br><br>
        <label>Password:</label><br>
        <input type="password" name="password"><br><br>
        <button type="submit">Sign in</button>
    </form>
    {% if message %}<p style="color:red;">{{ message }}</p>{% endif %}
</body>
</html>
"""


def init_db():
    """Creates the logging table if it doesn't already exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            username TEXT,
            password TEXT,
            user_agent TEXT,
            headers TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_attempt(ip_address: str, username: str, password: str, headers: dict):
    """Writes a single login attempt to the honeypot's own local database."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO login_attempts (timestamp, ip_address, username, password, user_agent, headers)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(),
            ip_address,
            username,
            password,
            headers.get("User-Agent", "unknown"),
            str(dict(headers)),
        ),
    )
    conn.commit()
    conn.close()


@app.route("/", methods=["GET"])
def index():
    return render_template_string(LOGIN_PAGE, message=None)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ip_address = request.remote_addr or "unknown"

    # Log everything about the attempt -- this is the entire point of the honeypot.
    log_attempt(ip_address, username, password, request.headers)

    # Always show a generic failure -- there is no real account to log into.
    return render_template_string(
        LOGIN_PAGE, message="Invalid username or password. Please try again."
    )


@app.route("/admin/logs", methods=["GET"])
def view_logs():
    """Simple internal view to review captured attempts (for the researcher only)."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT timestamp, ip_address, username, password, user_agent FROM login_attempts ORDER BY id DESC"
    ).fetchall()
    conn.close()

    html = "<h2>Honeypot Log</h2><table border=1 cellpadding=6>"
    html += "<tr><th>Time</th><th>IP</th><th>Username</th><th>Password</th><th>User-Agent</th></tr>"
    for row in rows:
        html += "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
    html += "</table>"
    return html


if __name__ == "__main__":
    init_db()
    print("Honeypot login page starting...")
    print("Fake login form: http://127.0.0.1:5000/")
    print("View captured attempts: http://127.0.0.1:5000/admin/logs")
    print("\nReminder: run this only on an isolated test VM. It is a decoy and")
    print("is intentionally NOT connected to any real database or auth system.")
    app.run(debug=True, port=5000)
