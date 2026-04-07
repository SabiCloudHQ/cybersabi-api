import databases
import sqlite3
import os

# APPSEC: Database file lives locally — in production this would be
# a connection string to PostgreSQL, stored in an environment variable.
DATABASE_URL = "sqlite:///./cybersabi.db"

database = databases.Database(DATABASE_URL)

def init_db():
    # Create tables if they don't exist
    # We use the sync sqlite3 here just for setup — not during requests
    conn = sqlite3.connect("cybersabi.db")
    cursor = conn.cursor()

    # Users table
    # APPSEC: We store hashed_password, never plain text.
    # The email column has a UNIQUE constraint — prevents duplicate accounts.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Login attempts table — for our brute-force tracking
    # APPSEC: Logging failed attempts to the database means they survive
    # server restarts — much better than in-memory tracking.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 0,
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    print("Database initialized.")