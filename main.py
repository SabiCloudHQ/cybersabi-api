from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt
import bcrypt
import datetime

# ─── App setup ────────────────────────────────────────────────────────────────
app = FastAPI()

# APPSEC: CORS controls which domains can call this API from a browser.
# Right now we only allow localhost:5173 (your React dev server).
# In production, change this to "https://cybersabi.app" only.
# Allowing "*" (all origins) lets any website call your API on behalf
# of a logged-in user — that's a CORS misconfiguration vulnerability.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── JWT config ───────────────────────────────────────────────────────────────
# APPSEC: This secret key signs JWT tokens.
# Anyone with this key can forge tokens and impersonate any user.
# In production: load this from an environment variable, NEVER hardcode it.
# Example: SECRET_KEY = os.environ.get("SECRET_KEY")
# We'll fix this in a later step — for now it's hardcoded to show the problem.
SECRET_KEY = "this-is-not-safe-change-me-in-production"
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30

# ─── Password hashing helpers ─────────────────────────────────────────────────
# APPSEC: bcrypt is slow by design — it makes brute-force attacks expensive.
# It also automatically generates a random salt per password, which means
# two users with the same password get different hashes (prevents rainbow tables).

def hash_password(plain: str) -> str:
    # APPSEC: bcrypt.hashpw needs bytes, not a string — encode first.
    # The gensalt() generates a unique random salt for each hash.
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    # APPSEC: bcrypt.checkpw does a constant-time comparison.
    # Using == to compare strings leaks timing information that attackers
    # can use to guess passwords — bcrypt's checkpw prevents that.
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

# ─── Fake user database ───────────────────────────────────────────────────────
# APPSEC: Passwords are stored as bcrypt hashes, never plain text.
# Even if someone dumps this entire dict, they can't reverse the hashes.
# Try printing hash_password("password123") — you'll get something like:
# $2b$12$eImiTXuWVxfM37uY4JANjQ...  (different every time due to random salt)
fake_users = {
    "student@cybersabi.app": {
        "email": "student@cybersabi.app",
        "hashed_password": hash_password("password123"),
        "name": "CyberSabi Student",
    }
}

# ─── Request / Response models ────────────────────────────────────────────────
# APPSEC: Pydantic models define exactly what shape of data each endpoint accepts.
# FastAPI automatically rejects requests that don't match — this is input validation.
# It prevents attackers from injecting extra fields to manipulate your logic.
class LoginRequest(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

# ─── Helper: create JWT ───────────────────────────────────────────────────────
def create_token(email: str) -> str:
    # APPSEC: JWT payload contains "claims" about the user.
    # Always include exp (expiry) — tokens without it are valid forever if stolen.
    # sub (subject) identifies who the token belongs to.
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": email,   # who this token belongs to
        "exp": expire,  # when it stops working
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# ─── Routes ───────────────────────────────────────────────────────────────────

# APPSEC: Health endpoint — confirm the API is alive.
# In production, never expose version numbers or stack info here —
# that helps attackers fingerprint your system.
@app.get("/health")
def health():
    return {"status": "ok"}

# APPSEC: POST /login — the authentication endpoint.
# Three rules for a secure login:
# 1. Same error message whether email is wrong OR password is wrong
#    (prevents username enumeration — attackers can't discover valid emails)
# 2. Always verify against the hash, never compare plain text
# 3. Return a short-lived signed token, not the user object
@app.post("/login", response_model=TokenResponse)
def login(body: LoginRequest):
    user = fake_users.get(body.email)

    # APPSEC: "Invalid email or password" — intentionally vague.
    # Never say "email not found" or "wrong password" separately.
    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token(body.email)

    # APPSEC: Return only the token. Never return the hashed password,
    # internal IDs, or any field the client doesn't need.
    return {"access_token": token, "token_type": "bearer"}

# APPSEC: GET /me — protected route placeholder.
# Next step: verify the JWT token from the Authorization header.
@app.get("/me")
def get_me():
    return {"message": "token verification coming next"}