from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from collections import defaultdict
from pydantic import BaseModel
from jose import jwt
from dotenv import load_dotenv
import bcrypt
import datetime
import time
import os
import sqlite3 as sqlite

# ─── Environment ──────────────────────────────────────────────────────────────
load_dotenv()

# APPSEC: Load secret from environment, never hardcode it.
# If SECRET_KEY is missing, we crash immediately rather than run insecurely.
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set. Refusing to start.")

ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30

# ─── App setup ────────────────────────────────────────────────────────────────
app = FastAPI()

# APPSEC: CORS controls which domains can call this API from a browser.
# Only allow localhost:5173 (your React dev server).
# In production, change this to "https://cybersabi.app" only.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Security Headers ─────────────────────────────────────────────────────────
# APPSEC: Using @app.middleware instead of BaseHTTPMiddleware avoids a known
# compatibility issue with newer Starlette versions and streaming responses.
# Both approaches add headers to every response — this one is more reliable.
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    # APPSEC: Content-Security-Policy — primary XSS defense.
    # Tells the browser which sources of scripts/styles/images are trusted.
    # Even if an attacker injects a <script> tag, the browser won't run it
    # unless the source is in this whitelist.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )

    # APPSEC: X-Frame-Options — prevents clickjacking.
    # Stops your app from being embedded in an <iframe> on an attacker's page.
    # An attacker could overlay an invisible iframe over a fake button and trick
    # users into clicking your real buttons without knowing it.
    response.headers["X-Frame-Options"] = "DENY"

    # APPSEC: X-Content-Type-Options — prevents MIME sniffing.
    # Without this, browsers might execute a response as JavaScript even if
    # the server says it's an image — called a MIME confusion attack.
    response.headers["X-Content-Type-Options"] = "nosniff"

    # APPSEC: Referrer-Policy — controls URL leakage.
    # Prevents internal URLs like /admin/users/123 from being sent to
    # third-party analytics or CDNs when a user clicks an external link.
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # APPSEC: Permissions-Policy — disables browser features you don't need.
    # If an attacker gets XSS, they still can't access camera/mic/location
    # because the browser policy blocks it at the platform level.
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), "
        "payment=(), usb=(), magnetometer=()"
    )

    # APPSEC: Remove the Server header — don't fingerprint your stack.
    # "Server: uvicorn" tells attackers exactly which CVEs to search for.
    if "server" in response.headers:
        del response.headers["server"]

    # APPSEC: HSTS — forces HTTPS only. Commented out for local dev.
    # Uncomment in production after confirming HTTPS works end to end.
    # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    return response

# ─── Password hashing ─────────────────────────────────────────────────────────
# APPSEC: bcrypt is slow by design — makes brute-force expensive.
# Random salt per password means identical passwords produce different hashes
# (prevents rainbow table attacks).

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    # APPSEC: checkpw uses constant-time comparison — prevents timing attacks.
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

# ─── Fake user database ───────────────────────────────────────────────────────
# APPSEC: Passwords stored as bcrypt hashes — never plain text.
fake_users = {
    "student@cybersabi.app": {
        "email": "student@cybersabi.app",
        "hashed_password": hash_password("password123"),
        "name": "CyberSabi Student",
    }
}

# ─── Brute-force protection ───────────────────────────────────────────────────
LOCKOUT_THRESHOLD = 5
EMAIL_LOCKOUT_THRESHOLD = 10
LOCKOUT_WINDOW = 15 * 60

failed_attempts = defaultdict(lambda: {"count": 0, "first_attempt": None})
failed_by_email = defaultdict(lambda: {"count": 0, "first_attempt": None})


def get_client_ip(request: Request) -> str:
    # APPSEC: Only trust X-Forwarded-For from your own infrastructure in production.
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


def is_locked_out(ip: str) -> tuple[bool, int]:
    record = failed_attempts[ip]
    if record["count"] >= LOCKOUT_THRESHOLD:
        elapsed = time.time() - record["first_attempt"]
        if elapsed < LOCKOUT_WINDOW:
            return True, int(LOCKOUT_WINDOW - elapsed)
        failed_attempts[ip] = {"count": 0, "first_attempt": None}
    return False, 0


def record_failure(ip: str):
    record = failed_attempts[ip]
    if record["count"] == 0:
        record["first_attempt"] = time.time()
    record["count"] += 1


def reset_attempts(ip: str):
    failed_attempts[ip] = {"count": 0, "first_attempt": None}


def is_email_locked(email: str) -> tuple[bool, int]:
    record = failed_by_email[email]
    if record["count"] >= EMAIL_LOCKOUT_THRESHOLD:
        elapsed = time.time() - record["first_attempt"]
        if elapsed < LOCKOUT_WINDOW:
            return True, int(LOCKOUT_WINDOW - elapsed)
        failed_by_email[email] = {"count": 0, "first_attempt": None}
    return False, 0


def record_email_failure(email: str):
    record = failed_by_email[email]
    if record["count"] == 0:
        record["first_attempt"] = time.time()
    record["count"] += 1


def reset_email_attempts(email: str):
    failed_by_email[email] = {"count": 0, "first_attempt": None}


# ─── Request models ───────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str


# ─── JWT helper ───────────────────────────────────────────────────────────────
def create_token(email: str) -> str:
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    payload = {"sub": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(body: LoginRequest, response: Response, request: Request):
    ip = get_client_ip(request)

    locked, seconds_remaining = is_locked_out(ip)
    if locked:
        minutes, seconds = seconds_remaining // 60, seconds_remaining % 60
        raise HTTPException(status_code=429, detail=f"Too many failed attempts. Try again in {minutes}m {seconds}s.")

    email_locked, email_seconds = is_email_locked(body.email)
    if email_locked:
        minutes, seconds = email_seconds // 60, email_seconds % 60
        raise HTTPException(status_code=429, detail=f"Too many failed attempts. Try again in {minutes}m {seconds}s.")

    user = fake_users.get(body.email)

    if not user or not verify_password(body.password, user["hashed_password"]):
        record_failure(ip)
        record_email_failure(body.email)
        current_count = failed_attempts[ip]["count"]
        remaining = LOCKOUT_THRESHOLD - current_count
        if remaining <= 0:
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 15 minutes.")
        # APPSEC: Same message for wrong email OR password — prevents username enumeration.
        raise HTTPException(status_code=401, detail=f"Invalid email or password. {remaining} attempt(s) remaining.")

    reset_attempts(ip)
    reset_email_attempts(body.email)

    token = create_token(body.email)
    # APPSEC: httpOnly cookie — JS cannot read it (XSS protection).
    # samesite=lax — CSRF protection. secure=False for local dev only.
    response.set_cookie(key="token", value=token, httponly=True, samesite="lax", secure=False, max_age=60 * TOKEN_EXPIRE_MINUTES)
    return {"message": "Login successful"}


@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("token")
    return {"message": "Logged out"}


@app.get("/me")
def get_me(request: Request):
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = fake_users.get(email)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return {"email": user["email"], "name": user["name"]}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# APPSEC: REMOVE IN PRODUCTION — exposes internal rate-limit state.
@app.get("/debug/attempts")
def debug_attempts(request: Request, email: str = "student@cybersabi.app"):
    ip = get_client_ip(request)
    ip_locked, ip_remaining = is_locked_out(ip)
    email_locked, email_remaining = is_email_locked(email)
    return {
        "ip": ip,
        "ip_failed_count": failed_attempts[ip]["count"],
        "ip_locked": ip_locked,
        "ip_seconds_remaining": ip_remaining,
        "email": email,
        "email_failed_count": failed_by_email[email]["count"],
        "email_locked": email_locked,
        "email_seconds_remaining": email_remaining,
    }


# ─── SQL injection demo + fix ─────────────────────────────────────────────────
# APPSEC: Fixed endpoint using parameterized queries.
# The vulnerable version concatenated user input into SQL directly — allowing
# OR bypass, UNION password dumps, and error-based fingerprinting.
# The fix: pass input as a ? parameter — it's always treated as a literal string.
@app.get("/users/search")
def search_users_safe(email: str):
    conn = sqlite.connect("cybersabi.db")
    cursor = conn.cursor()
    try:
        # SAFE: ? placeholder — input can never change the query structure
        cursor.execute("SELECT id, email, name FROM users WHERE email = ?", (email,))
        result = cursor.fetchall()
        conn.close()
        # APPSEC: Don't return the raw query — that's information disclosure
        return {"results": result}
    except Exception:
        conn.close()
        # APPSEC: Generic error — never expose the raw exception message
        return {"error": "Search failed"}
