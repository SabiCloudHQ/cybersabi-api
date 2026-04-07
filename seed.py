import sqlite3
import bcrypt

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

conn = sqlite3.connect("cybersabi.db")
cursor = conn.cursor()

# Create tables first
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        success INTEGER NOT NULL DEFAULT 0,
        attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

# Seed the user
cursor.execute(
    "INSERT OR IGNORE INTO users (email, hashed_password, name) VALUES (?, ?, ?)",
    ("student@cybersabi.app", hash_password("password123"), "CyberSabi Student")
)

conn.commit()
conn.close()
print("Database created and seeded: student@cybersabi.app / password123")
