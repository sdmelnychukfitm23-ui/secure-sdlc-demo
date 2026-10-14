from flask import Flask, request, render_template, redirect, session
from markupsafe import escape
from werkzeug.security import check_password_hash
import logging
import os
import sqlite3

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("auth")

app = Flask(__name__)
# FIXED (R4, STOR-1): секрет береться зі змінної оточення
app.secret_key = os.environ["SECRET_KEY"]
# FIXED (R6, CONF-1): безпечні cookie
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
)

DB_PATH = os.environ.get("DB_PATH", "demo.sqlite3")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.after_request
def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Server"] = "webserver"
    return resp


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    return f"<h1>Echo</h1><p>{escape(msg)}</p>"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    sql = "SELECT id, title, body FROM posts WHERE title LIKE ? OR body LIKE ?"
    pattern = f"%{q}%"
    rows = cur.execute(sql, (pattern, pattern)).fetchall()
    return render_template("search.html", q=q, rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        cur = conn.cursor()
        row = cur.execute("SELECT id, username, password FROM users WHERE username = ?", (username,)).fetchone()
        # FIXED (R3, AUTH-1): перевірка хешу, а не порівняння тексту
        if row and check_password_hash(row["password"], password):
            session["user_id"] = row["id"]
            # FIXED (LOG-1): журнал входів без паролів
            log.info("Успішний вхід: користувач=%r, IP=%s", username, request.remote_addr)
            return redirect("/profile")
        log.warning("Невдала спроба входу: користувач=%r, IP=%s", username, request.remote_addr)
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")
    conn = get_db()
    cur = conn.cursor()
    user = cur.execute("SELECT id, username FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template("profile.html", user=user)


if __name__ == "__main__":
    # FIXED (R5, CONF-1): без debug і лише локальний інтерфейс
    app.run(host="127.0.0.1", port=5000, debug=False)
