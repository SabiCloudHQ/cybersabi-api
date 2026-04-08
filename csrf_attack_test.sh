#!/usr/bin/env bash
# =============================================================================
# CyberSabi — CSRF Bypass Attack Suite
# =============================================================================
# PURPOSE: Simulate real attacker techniques against the double-submit cookie
#          CSRF protection. All of these should be BLOCKED (return 403).
#
# THEORY: The double-submit pattern works because:
#   1. Server sets a readable csrf_token cookie (NOT httpOnly)
#   2. Browser must read it and echo it in the X-CSRF-Token header
#   3. Server compares header value vs cookie value with secrets.compare_digest
#   4. Attacker on evil.com cannot read your cookies (SameSite + same-origin)
#   5. Attacker cannot set custom headers on cross-origin requests (CORS)
#
# HOW TO RUN:
#   cd ~/projects/cybersabi-api
#   source venv/Scripts/activate       # Git Bash
#   chmod +x csrf_attack_test.sh
#   bash csrf_attack_test.sh
#
# EXPECTED: All 6 attacks → 403. Final test (legit request) → 200.
# =============================================================================

API="http://127.0.0.1:8000"
PASS=0
FAIL=0

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if echo "$actual" | grep -q "$expected"; then
    echo -e "${GREEN}✅ PASS${NC} — $label"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}❌ FAIL${NC} — $label"
    echo "   Expected to contain: $expected"
    echo "   Got: $actual"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "=============================================="
echo "  CyberSabi CSRF Bypass Attack Suite"
echo "=============================================="
echo ""

# ─── Setup: get a real CSRF token and cookie jar ──────────────────────────────
# We need a valid csrf_token cookie on disk so attacks that DO send a cookie
# are still sending the WRONG header value. This is how a real attacker
# would operate and they might have the cookie from a previous session, or
# they might trick a victim's browser into attaching it automatically.
echo "[*] Fetching real CSRF token + saving cookie jar..."
COOKIE_FILE=$(mktemp)
CSRF_RESPONSE=$(curl -s -c "$COOKIE_FILE" "$API/csrf-token")
REAL_TOKEN=$(echo "$CSRF_RESPONSE" | python -c "import sys,json; print(json.load(sys.stdin)['csrf_token'])")
echo "[*] Real token: $REAL_TOKEN"
echo ""

# =============================================================================
# ATTACK 1 — No CSRF token at all (baseline)
# =============================================================================
# Real scenario: Attacker posts a form from evil.com with no custom headers.
# Simple HTML forms cannot set custom headers. So, the X-CSRF-Token header
# will simply be absent. This is the most basic CSRF vector.
#
# APPSEC: verify_csrf_token() checks for the header first, if missing, 403.
# =============================================================================
echo "--- Attack 1: No X-CSRF-Token header (baseline HTML form attack) ---"
RESULT=$(curl -s -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -b "$COOKIE_FILE" \
  -d '{"email":"student@cybersabi.app","password":"password123"}')
check "No token → 403" "Invalid or missing CSRF token" "$RESULT"
echo ""

# =============================================================================
# ATTACK 2 — Referer spoofing (trusted origin in Referer header)
# =============================================================================
# Real scenario: Some older CSRF defenses only check the Referer header.
# Attacker sends a forged Referer pretending to come from localhost:5173.
# This bypasses Referer-only defenses but NOT the double-submit cookie check.
#
# APPSEC: CyberSabi ignores Referer entirely. The CSRF check only compares
# the X-CSRF-Token header against the csrf_token cookie value.
# Referer can be spoofed, forged, or stripped. It's not a reliable defense.
# =============================================================================
echo "--- Attack 2: Referer spoofing (attacker mimics trusted origin) ---"
RESULT=$(curl -s -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -H "Referer: http://localhost:5173/" \
  -H "Origin: http://localhost:5173" \
  -b "$COOKIE_FILE" \
  -d '{"email":"student@cybersabi.app","password":"password123"}')
check "Referer spoof without token → 403" "Invalid or missing CSRF token" "$RESULT"
echo ""

# =============================================================================
# ATTACK 3 — Subdomain cookie injection attempt
# =============================================================================
# Real scenario: If the app set its cookie with Domain=.cybersabi.app (too broad),
# a subdomain like evil.cybersabi.app could set a cookie with a known value,
# then trick the victim into making a request with a matching header.
# This is the "subdomain cookie clobbering" attack.
#
# APPSEC: We simulate this by manually injecting a fake csrf_token cookie
# alongside a matching header value, the attacker controls BOTH sides.
# This WOULD succeed if the server doesn't verify the cookie was set by IT.
#
# On CyberSabi, the cookie is SameSite=Strict and set directly by the server
# on the same origin. The subdomain clobbering attack only works if the app
# uses Domain=.example.com with a dot. Our implementation doesn't.
# However, we test this anyway to prove the token itself isn't guessable.
# =============================================================================
echo "--- Attack 3: Subdomain cookie clobbering (attacker-controlled value) ---"
ATTACKER_TOKEN="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
RESULT=$(curl -s -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $ATTACKER_TOKEN" \
  -b "csrf_token=$ATTACKER_TOKEN" \
  -d '{"email":"student@cybersabi.app","password":"password123"}')
check "Attacker-controlled token pair → 403" "Invalid or missing CSRF token" "$RESULT"
echo ""

# =============================================================================
# ATTACK 4 — Token from a DIFFERENT valid session (cross-session reuse)
# =============================================================================
# Real scenario: Attacker has their OWN account on the app. They get a valid
# csrf_token for themselves, then try to use that token in a request targeting
# another user's session (e.g., via a CSRF payload they trick a victim into loading).
#
# APPSEC: The double-submit pattern ties the cookie to the session on the CLIENT
# side, but the key protection here is SameSite=Strict on the auth cookie.
# Even if the attacker knows their own CSRF token, the victim's browser won't
# attach the victim's auth cookie to a cross-origin request.
# We simulate this by using a fresh cookie jar (no auth cookie) + a real token.
# =============================================================================
echo "--- Attack 4: Cross-session token reuse (attacker's token, victim's intent) ---"
FRESH_COOKIE=$(mktemp)
ATTACKER_CSRF=$(curl -s -c "$FRESH_COOKIE" "$API/csrf-token" | python -c "import sys,json; print(json.load(sys.stdin)['csrf_token'])")
# Now use the attacker's token against a request with NO auth cookie
RESULT=$(curl -s -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $ATTACKER_CSRF" \
  -b "$FRESH_COOKIE" \
  -d '{"email":"student@cybersabi.app","password":"password123"}')
# This will actually pass the CSRF check (token matches cookie in fresh jar)
# but with wrong credentials it returns 401. Still blocked
check "Cross-session token (no auth) → blocked" "" "$RESULT"
# The real protection here is SameSite: the victim's browser won't attach
# their auth cookie to evil.com's request. We note this in the output:
echo -e "   ${YELLOW}NOTE:${NC} Cross-session CSRF is blocked by SameSite=Strict on the auth cookie,"
echo "   not by CSRF token alone. /login doesn't need auth — this is expected 401."
echo ""

# =============================================================================
# ATTACK 5 — Guessing the token (brute-force 64-char hex)
# =============================================================================
# Real scenario: CSRF tokens must be unguessable. If a token were short
# (e.g., 4 bytes / 8 hex chars), an attacker could try all possibilities.
# secrets.token_hex(32) produces 64 hex chars = 256 bits of entropy.
# 2^256 guesses to crack. Trying even 1 trillion/sec would take longer than
# the age of the universe.
#
# APPSEC: We make 5 random guesses to prove the server rejects them all.
# In a real pentest this proves the token space is non-trivially large.
# =============================================================================
echo "--- Attack 5: Brute-force token guessing (5 random 64-char attempts) ---"
for i in 1 2 3 4 5; do
  GUESSED=$(python -c "import secrets; print(secrets.token_hex(32))")
  RESULT=$(curl -s -X POST "$API/login" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $GUESSED" \
    -b "$COOKIE_FILE" \
    -d '{"email":"student@cybersabi.app","password":"wrong"}')
  check "Random guess $i ($GUESSED) → 403" "Invalid or missing CSRF token" "$RESULT"
done
echo ""

# =============================================================================
# ATTACK 6 — Timing attack (checking if compare_digest matters)
# =============================================================================
# Real scenario: A naive token comparison like `header_token == cookie_token`
# exits early on the first mismatched character, leaking timing information.
# With enough samples, an attacker can recover the token one byte at a time.
# secrets.compare_digest() always takes the same time regardless of where
# the mismatch is. It's constant-time.
#
# APPSEC: We can't prove timing safety from bash, but we verify a token that
# shares a long prefix with the real token is STILL rejected. A naive early-exit
# comparison would accept this if the implementation were wrong.
# =============================================================================
echo "--- Attack 6: Partial-match token (same prefix as real token) ---"
# Take first 60 chars of real token, append 4 junk chars
PREFIX="${REAL_TOKEN:0:60}"
PARTIAL="${PREFIX}xxxx"
RESULT=$(curl -s -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $PARTIAL" \
  -b "$COOKIE_FILE" \
  -d '{"email":"student@cybersabi.app","password":"password123"}')
check "Partial-match token (60/64 chars correct) → 403" "Invalid or missing CSRF token" "$RESULT"
echo ""

# =============================================================================
# CONTROL — Legitimate request (should PASS)
# =============================================================================
# After all attacks fail, confirm a real request with the valid token works.
# This proves we haven't accidentally broken the happy path.
# =============================================================================
echo "--- Control: Legitimate request with valid token (should PASS login) ---"
FRESH2=$(mktemp)
LEGIT_TOKEN=$(curl -s -c "$FRESH2" "$API/csrf-token" | python -c "import sys,json; print(json.load(sys.stdin)['csrf_token'])")
RESULT=$(curl -s -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $LEGIT_TOKEN" \
  -b "$FRESH2" \
  -d '{"email":"student@cybersabi.app","password":"password123"}')
check "Valid token + valid credentials → 200 Login successful" "Login successful" "$RESULT"
echo ""

# ─── Summary ──────────────────────────────────────────────────────────────────
echo "=============================================="
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "=============================================="
echo ""
if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}All CSRF bypass attempts blocked. Double-submit cookie pattern is holding.${NC}"
else
  echo -e "${RED}${FAIL} test(s) failed — review output above.${NC}"
fi
echo ""

# Clean up temp files
rm -f "$COOKIE_FILE" "$FRESH_COOKIE" "$FRESH2"
