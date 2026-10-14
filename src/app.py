from flask import Flask, request, render_template, redirect, make_response, session
from markupsafe import escape
import os
import sqlite3

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "hardcoded-dev-secret")  # intentionally weak

DB_PATH = os.environ.get("DB_PATH", "demo.sqlite3")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.after_request
def set_security_headers(resp):
    # FIXED (R2, CONF-1): заголовки безпеки
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
    # FIXED (R2): екранування користувацького вводу
    msg = request.args.get("msg", "")
    return f"<h1>Echo</h1><p>{escape(msg)}</p>"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    # FIXED (R1): параметризований запит замість f-рядка
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
        # Passwords stored in plaintext (intentionally bad)
        row = cur.execute("SELECT id, username, password FROM users WHERE username = ?", (username,)).fetchone()
        if row and row["password"] == password:
            session["user_id"] = row["id"]
            resp = make_response(redirect("/profile"))
            # Missing security flags intentionally
            return resp
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
    app.run(host="0.0.0.0", port=5000, debug=True)
