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
# Allowing "*" lets any website call your API on behalf of a logged-in user —
# that's a CORS misconfiguration vulnerability.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Password hashing ─────────────────────────────────────────────────────────
# APPSEC: bcrypt is slow by design — makes brute-force attacks expensive.
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
# APPSEC: Track failed attempts in memory — simple for learning.
# In production use Redis so counts persist across restarts and multiple servers.

LOCKOUT_THRESHOLD = 5        # IP lockout after this many failures
EMAIL_LOCKOUT_THRESHOLD = 10 # Email lockout — higher to reduce DoS risk
LOCKOUT_WINDOW = 15 * 60     # 15 minutes in seconds

# Track by IP — stops single-source attacks
failed_attempts = defaultdict(lambda: {"count": 0, "first_attempt": None})

# Track by email — catches distributed attacks where attacker rotates IPs
# FIX: declared once here only (duplicate declarations removed)
failed_by_email = defaultdict(lambda: {"count": 0, "first_attempt": None})


def get_client_ip(request: Request) -> str:
    # APPSEC: X-Forwarded-For is set by load balancers/proxies.
    # Only trust this header from your own infrastructure in production —
    # attackers can spoof it if you accept it blindly from anywhere.
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
        else:
            failed_attempts[ip] = {"count": 0, "first_attempt": None}
    return False, 0


def record_failure(ip: str):
    record = failed_attempts[ip]
    if record["count"] == 0:
        record["first_attempt"] = time.time()
    record["count"] += 1


def reset_attempts(ip: str):
    # APPSEC: Reset on success so legitimate users aren't permanently locked.
    failed_attempts[ip] = {"count": 0, "first_attempt": None}


def is_email_locked(email: str) -> tuple[bool, int]:
    record = failed_by_email[email]
    if record["count"] >= EMAIL_LOCKOUT_THRESHOLD:
        elapsed = time.time() - record["first_attempt"]
        if elapsed < LOCKOUT_WINDOW:
            return True, int(LOCKOUT_WINDOW - elapsed)
        else:
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
# APPSEC: Pydantic models enforce input shape — FastAPI rejects anything
# that doesn't match. This is input validation against injection attacks.
class LoginRequest(BaseModel):
    email: str
    password: str


# ─── JWT helper ───────────────────────────────────────────────────────────────
def create_token(email: str) -> str:
    # APPSEC: Always include exp — tokens without expiry are valid forever if stolen.
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": email,   # who this token belongs to
        "exp": expire,  # when it stops working
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# ─── Routes ───────────────────────────────────────────────────────────────────

# APPSEC: Never expose version numbers or stack info in health endpoints —
# helps attackers fingerprint your system.
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(body: LoginRequest, response: Response, request: Request):
    ip = get_client_ip(request)

    # APPSEC: Check IP lockout first — single-source brute-force
    locked, seconds_remaining = is_locked_out(ip)
    if locked:
        minutes = seconds_remaining // 60
        seconds = seconds_remaining % 60
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {minutes}m {seconds}s."
        )

    # APPSEC: Check email lockout — distributed brute-force across many IPs
    email_locked, email_seconds = is_email_locked(body.email)
    if email_locked:
        minutes = email_seconds // 60
        seconds = email_seconds % 60
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {minutes}m {seconds}s."
        )

    user = fake_users.get(body.email)

    if not user or not verify_password(body.password, user["hashed_password"]):
        # APPSEC: Record failure against BOTH IP and email
        record_failure(ip)
        record_email_failure(body.email)

        current_count = failed_attempts[ip]["count"]
        remaining_attempts = LOCKOUT_THRESHOLD - current_count

        if remaining_attempts <= 0:
            raise HTTPException(
                status_code=429,
                detail="Too many failed attempts. Try again in 15 minutes."
            )

        # APPSEC: Same message for wrong email OR wrong password — prevents
        # username enumeration (attacker can't tell which field was wrong).
        raise HTTPException(
            status_code=401,
            detail=f"Invalid email or password. {remaining_attempts} attempt(s) remaining."
        )

    # APPSEC: Reset BOTH counters on success
    reset_attempts(ip)
    reset_email_attempts(body.email)

    token = create_token(body.email)

    # APPSEC: httpOnly=True — JavaScript cannot read this cookie (XSS protection)
    # samesite="lax" — CSRF protection
    # secure=False — HTTP allowed locally; set True in production (HTTPS only)
    response.set_cookie(
        key="token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * TOKEN_EXPIRE_MINUTES,
    )
    return {"message": "Login successful"}


# APPSEC: Logout clears the cookie server-side — more secure than
# localStorage where the client controls deletion.
@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("token")
    return {"message": "Logged out"}


@app.get("/me")
def get_me(request: Request):
    # APPSEC: Read token from cookie — never from query params (they appear in logs).
    token = request.cookies.get("token")

    # APPSEC: 401 = not authenticated | 403 = authenticated but not authorized
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # APPSEC: jwt.decode verifies signature AND expiry automatically.
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")

        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")

        # APPSEC: Always re-fetch the user — they may have been deleted/suspended
        # after the token was issued.
        user = fake_users.get(email)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        # APPSEC: Return only what the frontend needs — never hashed password
        # or internal fields.
        return {"email": user["email"], "name": user["name"]}

    except HTTPException:
        raise

    except Exception:
        # APPSEC: Same vague error for all token failures — never reveal why.
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# APPSEC: REMOVE THIS IN PRODUCTION.
# Exposes internal rate-limit state — useful for learning, dangerous in prod.
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
