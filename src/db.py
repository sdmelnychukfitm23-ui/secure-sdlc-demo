import sqlite3, os, pathlib
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get("DB_PATH", "demo.sqlite3")

pathlib.Path(DB_PATH).unlink(missing_ok=True)
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.executescript(
    '''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL  -- хеш пароля з сіллю (PBKDF2)
    );
    CREATE TABLE posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT NOT NULL
    );
    INSERT INTO posts(title, body) VALUES
        ('Welcome', 'This is a demo post.'),
        ('Security Tips', 'Never trust user input. Use parameterized queries.');
    '''
)

# FIXED (R3): паролі зберігаються лише як хеші
for name, pw in [("alice", "alice123"), ("bob", "bob12345")]:
    cur.execute(
        "INSERT INTO users(username, password) VALUES (?, ?)",
        (name, generate_password_hash(pw, method="pbkdf2:sha256")),
    )

conn.commit()
conn.close()
print(f"Initialized SQLite DB at {DB_PATH}")
