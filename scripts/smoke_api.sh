#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"

need () { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
need curl
need jq

echo "== KMS-IAM smoke test (API) =="
echo "BASE_URL=$BASE_URL"
echo

status_code () { echo "$1" | head -n 1 | awk '{print $2}'; }
body_only () { echo "$1" | sed -n '/^\r\{0,1\}$/,$p' | tail -n +2; }
expect () {
  local got="$1" expected="$2" msg="$3"
  if [[ "$got" != "$expected" ]]; then
    echo "FAIL: $msg (expected $expected, got $got)"
    exit 1
  fi
}

login () {
  local user="$1" pass="$2"
  curl -sS -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$user\",\"password\":\"$pass\"}" | jq -r .access_token
}

post_json () {
  local url="$1" token="$2" data="$3"
  curl -sS -i -X POST "$url" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "$data"
}

get_auth () {
  local url="$1" token="$2"
  curl -sS -i -X GET "$url" -H "Authorization: Bearer $token"
}

echo "[0] Health"
curl -sS "$BASE_URL/health" | jq .
echo

echo "[1] Login users (must already exist)"
ADMIN_TOKEN="$(login admin 'AdminPass123!')"
ALICE_TOKEN="$(login alice 'Alice123!')"
BOB_TOKEN="$(login bob 'Bob123!')"

[[ "$ADMIN_TOKEN" == "null" ]] && { echo "Admin login failed"; exit 1; }
[[ "$ALICE_TOKEN" == "null" ]] && { echo "Alice login failed"; exit 1; }
[[ "$BOB_TOKEN" == "null" ]] && { echo "Bob login failed"; exit 1; }

echo "  admin OK"
echo "  alice OK"
echo "  bob OK"
echo

echo "[2] RBAC IAM: alice (key_manager) cannot assign roles (403 expected)"
RESP="$(post_json "$BASE_URL/auth/assign-role" "$ALICE_TOKEN" '{"username":"bob","role_name":"key_user"}')"
SC="$(status_code "$RESP")"
expect "$SC" "403" "alice assign-role"
echo "  OK"
echo

echo "[3] RBAC KMS: bob (key_user) cannot create keys (403 expected)"
RESP="$(post_json "$BASE_URL/keys/create" "$BOB_TOKEN" '{"name":"bob-should-fail","allowed_ops":["encrypt","decrypt"],"rotation_days":90}')"
SC="$(status_code "$RESP")"
expect "$SC" "403" "bob create key"
echo "  OK"
echo

echo "[4] Create key with alice (200 expected)"
RESP="$(post_json "$BASE_URL/keys/create" "$ALICE_TOKEN" '{"name":"smoke-key","allowed_ops":["encrypt","decrypt"],"rotation_days":90}')"
SC="$(status_code "$RESP")"
expect "$SC" "200" "alice create key"
BODY="$(body_only "$RESP")"
KEY_ID="$(echo "$BODY" | jq -r .id)"
echo "  KEY_ID=$KEY_ID"
echo

echo "[5] Encrypt+Decrypt with bob (200 expected + plaintext matches)"
PLAINTEXT_B64="SGVsbG8gV29ybGQ="

RESP="$(post_json "$BASE_URL/keys/encrypt" "$BOB_TOKEN" "{\"key_id\":\"$KEY_ID\",\"plaintext_b64\":\"$PLAINTEXT_B64\"}")"
SC="$(status_code "$RESP")"
expect "$SC" "200" "bob encrypt"
ENC_BODY="$(body_only "$RESP")"

CIPHERTEXT_B64="$(echo "$ENC_BODY" | jq -r .ciphertext_b64)"
IV_B64="$(echo "$ENC_BODY" | jq -r .iv_b64)"
TAG_B64="$(echo "$ENC_BODY" | jq -r .tag_b64)"

RESP="$(post_json "$BASE_URL/keys/decrypt" "$BOB_TOKEN" "{\"key_id\":\"$KEY_ID\",\"ciphertext_b64\":\"$CIPHERTEXT_B64\",\"iv_b64\":\"$IV_B64\",\"tag_b64\":\"$TAG_B64\"}")"
SC="$(status_code "$RESP")"
expect "$SC" "200" "bob decrypt"
DEC_BODY="$(body_only "$RESP")"
DEC_PLAINTEXT_B64="$(echo "$DEC_BODY" | jq -r .plaintext_b64)"

if [[ "$DEC_PLAINTEXT_B64" != "$PLAINTEXT_B64" ]]; then
  echo "FAIL: decrypt mismatch"
  echo "Expected: $PLAINTEXT_B64"
  echo "Got:      $DEC_PLAINTEXT_B64"
  exit 1
fi
echo "  OK"
echo

echo "[6] Rotate RBAC: bob forbidden (403), alice allowed (200)"
RESP="$(curl -sS -i -X POST "$BASE_URL/keys/$KEY_ID/rotate" -H "Authorization: Bearer $BOB_TOKEN")"
SC="$(status_code "$RESP")"
expect "$SC" "403" "bob rotate"
echo "  OK: bob rotate forbidden"

RESP="$(curl -sS -i -X POST "$BASE_URL/keys/$KEY_ID/rotate" -H "Authorization: Bearer $ALICE_TOKEN")"
SC="$(status_code "$RESP")"
expect "$SC" "200" "alice rotate"
ROT_BODY="$(body_only "$RESP")"
NEW_KEY_ID="$(echo "$ROT_BODY" | jq -r .new_key_id)"
echo "  OK: alice rotated -> NEW_KEY_ID=$NEW_KEY_ID"
echo

echo "[7] Audit logs: alice forbidden (403), admin allowed (200) and contains KEY_* events"
RESP="$(get_auth "$BASE_URL/audit/logs?limit=20" "$ALICE_TOKEN")"
SC="$(status_code "$RESP")"
expect "$SC" "403" "alice view audit logs"
echo "  OK: alice forbidden"

RESP="$(get_auth "$BASE_URL/audit/logs?limit=200" "$ADMIN_TOKEN")"
SC="$(status_code "$RESP")"
expect "$SC" "200" "admin view audit logs"
AUD_BODY="$(body_only "$RESP")"

KEY_EVENTS_COUNT="$(echo "$AUD_BODY" | jq '[.logs[] | select(.action | startswith("KEY_"))] | length')"
if [[ "$KEY_EVENTS_COUNT" -lt 1 ]]; then
  echo "FAIL: expected at least 1 KEY_* audit event"
  exit 1
fi
echo "  OK: KEY_* audit events count=$KEY_EVENTS_COUNT"
echo

echo "== SMOKE TEST PASSED =="
