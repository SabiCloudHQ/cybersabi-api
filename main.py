from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt
from dotenv import load_dotenv
import bcrypt
import datetime
import os

# ─── Environment ──────────────────────────────────────────────────────────────
load_dotenv()  # reads .env file into environment

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
    allow_credentials=True,   # Required for cookies to work cross-origin
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Password hashing helpers ─────────────────────────────────────────────────
# APPSEC: bcrypt is slow by design — it makes brute-force attacks expensive.
# It auto-generates a random salt per password so identical passwords produce
# different hashes (prevents rainbow table attacks).

def hash_password(plain: str) -> str:
    # APPSEC: bcrypt.hashpw needs bytes — encode first.
    # gensalt() generates a unique random salt for each hash.
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    # APPSEC: checkpw uses constant-time comparison.
    # Using == to compare strings leaks timing info attackers can exploit.
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

# ─── Fake user database ───────────────────────────────────────────────────────
# APPSEC: Passwords stored as bcrypt hashes — never plain text.
# Even a full database dump can't be reversed without brute-forcing each hash.
fake_users = {
    "student@cybersabi.app": {
        "email": "student@cybersabi.app",
        "hashed_password": hash_password("password123"),
        "name": "CyberSabi Student",
    }
}

# ─── Request models ───────────────────────────────────────────────────────────
# APPSEC: Pydantic models define exactly what shape this endpoint accepts.
# FastAPI automatically rejects anything that doesn't match — this is input
# validation, one of the most important AppSec defenses against injection attacks.
class LoginRequest(BaseModel):
    email: str
    password: str

# ─── Helper: create JWT ───────────────────────────────────────────────────────
def create_token(email: str) -> str:
    # APPSEC: Always include exp (expiry) — tokens without it are valid forever
    # if stolen. sub (subject) identifies who the token belongs to.
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": email,   # who this token belongs to
        "exp": expire,  # when it stops working
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# ─── Routes ───────────────────────────────────────────────────────────────────

# APPSEC: Health endpoint — never expose version numbers or stack details here.
# That information helps attackers fingerprint your system.
@app.get("/health")
def health():
    return {"status": "ok"}

# APPSEC: POST /login — three rules for a secure login:
# 1. Same error for wrong email OR wrong password (prevents username enumeration)
# 2. Verify against bcrypt hash, never compare plain text
# 3. Set token as httpOnly cookie — never return it in the response body
@app.post("/login")
def login(body: LoginRequest, response: Response):
    user = fake_users.get(body.email)

    # APPSEC: "Invalid email or password" — intentionally vague.
    # Separate messages ("email not found" vs "wrong password") let attackers
    # enumerate valid accounts by trying different inputs.
    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token(body.email)

    # APPSEC: httpOnly cookie — JavaScript cannot read this at all.
    # Even a successful XSS attack cannot steal this token.
    # samesite="lax" adds CSRF protection — cookie only sent on same-site requests.
    # secure=False for local dev only — set True in production (HTTPS required).
    response.set_cookie(
        key="token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,               # Change to True in production
        max_age=60 * TOKEN_EXPIRE_MINUTES,
    )

    # APPSEC: Return only a success message — never the token in the body.
    # The token travels in the cookie only, invisible to JavaScript.
    return {"message": "Login successful"}

# APPSEC: POST /logout — clears the cookie server-side.
# More secure than localStorage where the client controls deletion.
@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("token")
    return {"message": "Logged out"}

# APPSEC: GET /me — protected route.
# Reads the httpOnly cookie, verifies the JWT signature and expiry,
# confirms the user still exists, then returns safe user data.
@app.get("/me")
def get_me(request: Request):
    # APPSEC: Read token from cookie — browser sends it automatically.
    # Never accept tokens from query params (?token=...) — they appear in logs.
    token = request.cookies.get("token")

    # APPSEC: 401 = not authenticated (no valid identity)
    # 403 = authenticated but not authorized (right identity, wrong permission)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # APPSEC: jwt.decode verifies two things:
        # 1. Signature — was this signed with our SECRET_KEY?
        # 2. Expiry — has it expired?
        # Either failure raises an exception — caught below.
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")

        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")

        # APPSEC: Always look up the user in the database even with a valid token.
        # The user may have been deleted or suspended after the token was issued.
        user = fake_users.get(email)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        # APPSEC: Return only what the frontend needs — never the hashed password
        # or any internal fields.
        return {"email": user["email"], "name": user["name"]}

    except HTTPException:
        raise  # re-raise intentional 401s from above

    except Exception:
        # APPSEC: Any token error (expired, tampered, wrong signature) returns
        # the same vague 401. Never reveal WHY the token was rejected.
        raise HTTPException(status_code=401, detail="Invalid or expired token")
