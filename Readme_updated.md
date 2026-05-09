# KMS-IAM: Cryptographic Key Management with Mini-IAM

## Project status

This README reflects what is currently implemented and tested in this repository.

Implemented:
- JWT auth and user management (`/auth/register`, `/auth/login`, `/auth/assign-role`)
- RBAC with roles `admin`, `key_manager`, `key_user`
- KMS key lifecycle (`create`, `list`, `encrypt`, `decrypt`, `rotate`)
- Audit logging for security-sensitive operations and denied actions
- API smoke scripts (with and without bootstrap)
- Automated tests for M3 (keys) and M4 (audit)

## What is done

### 1) Authentication and JWT (done)
- `app/api/auth.py` uses `get_current_user` to validate bearer token and resolve user from DB.
- Keys endpoints rely on the real authenticated user (`current_user["id"]`), not a test placeholder.
- `/auth/assign-role` is admin-only and returns `403` for non-admin users.

### 2) RBAC policy (done)
- `app/iam/policy.py` defines role-based permissions:
  - `admin`: full access
  - `key_manager`: create/list/rotate/encrypt/decrypt
  - `key_user`: list/encrypt/decrypt
- Access checks are enforced in `app/api/keys.py` and `app/api/audit.py`.

### 3) KMS operations and key lifecycle (done)
- `app/kms/key_manager.py` supports:
  - key creation (AES-256-GCM envelope-protected material)
  - encryption and decryption
  - rotation with new version creation
- `allowed_ops` validation exists and rejects invalid operations.
- Rotation behavior keeps old key usable for decrypt while preventing old-version encrypt.

### 4) Audit logging (done)
- `app/audit/logger.py` records events into `data/audit.log`.
- Denied RBAC actions are logged (`success=false`) with reason details.
- Admin audit APIs:
  - `GET /audit/logs`
  - `GET /audit/stats`
- Non-admin access to these endpoints is denied and audited.

### 5) Tests and smoke coverage (done)
- `tests/test_m3_keys.py` covers key-flow scenarios (invalid ops, rotate errors, success path).
- `tests/test_m4_audit.py` covers audit behavior (forbidden actions + admin-only logs).
- The provided test output confirms `tests/test_m4_audit.py` passing.
- End-to-end scripts:
  - `scripts/smoke_api.sh`
  - `scripts/smoke_api_bootstrap.sh`

## API endpoints

### Auth
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/assign-role` (admin only)

### Keys
- `POST /keys/create`
- `GET /keys/`
- `POST /keys/encrypt`
- `POST /keys/decrypt`
- `POST /keys/{key_id}/rotate`

### Audit
- `GET /audit/logs` (admin only)
- `GET /audit/stats` (admin only)

### Utility
- `GET /`
- `GET /health`
- `GET /docs`

## Quick start (WSL / Linux shell)

```bash
cd /mnt/c/Users/farah/KMS_IAM
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn sqlalchemy cryptography bcrypt pyjwt python-dotenv
pip install -r requirements-dev.txt
```

Initialize DB + roles:

```bash
cd /mnt/c/Users/farah/KMS_IAM
source venv/bin/activate
PYTHONPATH=. python3 scripts/init_db.py
python3 scripts/init_roles.py
```

Run API:

```bash
cd /mnt/c/Users/farah/KMS_IAM
source venv/bin/activate
python3 -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Quick verification commands

Set base URL:

```bash
BASE_URL="http://localhost:8000"
```

1) Without token, key creation should return `401`:

```bash
curl -i -X POST "$BASE_URL/keys/create" \
  -H "Content-Type: application/json" \
  -d '{"name":"no-token","allowed_ops":["encrypt","decrypt"],"rotation_days":90}'
```

2) Login users:

```bash
ADMIN_TOKEN="$(curl -s -X POST "$BASE_URL/auth/login" -H "Content-Type: application/json" -d '{"username":"admin","password":"AdminPass123!"}' | jq -r .access_token)"
ALICE_TOKEN="$(curl -s -X POST "$BASE_URL/auth/login" -H "Content-Type: application/json" -d '{"username":"alice","password":"Alice123!"}' | jq -r .access_token)"
BOB_TOKEN="$(curl -s -X POST "$BASE_URL/auth/login" -H "Content-Type: application/json" -d '{"username":"bob","password":"Bob123!"}' | jq -r .access_token)"
```

3) `key_user` cannot create keys (`403` expected):

```bash
curl -i -X POST "$BASE_URL/keys/create" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"bob-no-create","allowed_ops":["encrypt","decrypt"],"rotation_days":90}'
```

4) `key_manager` creates key:

```bash
KEY_ID="$(curl -s -X POST "$BASE_URL/keys/create" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-key","allowed_ops":["encrypt","decrypt"],"rotation_days":90}' | jq -r .id)"
echo "$KEY_ID"
```

5) Encrypt/decrypt with `key_user` on existing key:

```bash
PLAINTEXT_B64="SGVsbG8gV29ybGQ="
ENC="$(curl -s -X POST "$BASE_URL/keys/encrypt" -H "Authorization: Bearer $BOB_TOKEN" -H "Content-Type: application/json" -d "{\"key_id\":\"$KEY_ID\",\"plaintext_b64\":\"$PLAINTEXT_B64\"}")"
CIPHERTEXT_B64="$(echo "$ENC" | jq -r .ciphertext_b64)"
IV_B64="$(echo "$ENC" | jq -r .iv_b64)"
TAG_B64="$(echo "$ENC" | jq -r .tag_b64)"
curl -s -X POST "$BASE_URL/keys/decrypt" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"key_id\":\"$KEY_ID\",\"ciphertext_b64\":\"$CIPHERTEXT_B64\",\"iv_b64\":\"$IV_B64\",\"tag_b64\":\"$TAG_B64\"}"
```

6) Rotate check: bob forbidden, alice allowed:

```bash
curl -i -X POST "$BASE_URL/keys/$KEY_ID/rotate" -H "Authorization: Bearer $BOB_TOKEN"
curl -i -X POST "$BASE_URL/keys/$KEY_ID/rotate" -H "Authorization: Bearer $ALICE_TOKEN"
```

7) Audit endpoint check:

```bash
curl -i -X GET "$BASE_URL/audit/logs?limit=20" -H "Authorization: Bearer $ALICE_TOKEN"
curl -i -X GET "$BASE_URL/audit/logs?limit=20" -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Smoke scripts

Run with existing users:

```bash
cd /mnt/c/Users/farah/KMS_IAM
source venv/bin/activate
chmod +x scripts/smoke_api.sh
BASE_URL="http://localhost:8000" ./scripts/smoke_api.sh
```

Run with bootstrap (creates/ensures users + role assignments):

```bash
cd /mnt/c/Users/farah/KMS_IAM
source venv/bin/activate
chmod +x scripts/smoke_api_bootstrap.sh
BASE_URL="http://localhost:8000" ./scripts/smoke_api_bootstrap.sh
```

## Troubleshooting (from actual project run)

1) `ModuleNotFoundError: No module named 'app'` when running `scripts/init_db.py`
- Use:

```bash
PYTHONPATH=. python3 scripts/init_db.py
```

2) `uvicorn: command not found`
- Run inside venv with module form:

```bash
python3 -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

3) `/usr/bin/env: 'bash\r': No such file or directory`
- Script has CRLF line endings; convert to LF:

```bash
sed -i 's/\r$//' scripts/smoke_api_bootstrap.sh
sed -i 's/\r$//' scripts/smoke_api.sh
```

4) `sqlite3.OperationalError: unable to open database file`
- Ensure `data/` exists and app runs from project root.
- Keep `DATABASE_URL` consistent with working directory.

5) JSON parsing issues with curl on PowerShell
- Prefer WSL bash for JSON-heavy curl commands.

## Repository structure

```text
app/
  api/
    auth.py
    keys.py
    audit.py
  audit/
    logger.py
  crypto/
    core.py
  iam/
    manager.py
    policy.py
  kms/
    key_manager.py
  models/
  config.py
  database.py
  main.py
scripts/
  init_db.py
  init_roles.py
  smoke_api.sh
  smoke_api_bootstrap.sh
tests/
  conftest.py
  test_m3_keys.py
  test_m4_audit.py
data/
  kms-iam.db
  audit.log
```

## Next steps (suggested)

- Replace deprecated `datetime.utcnow()` usage with timezone-aware UTC timestamps.
- Update SQLAlchemy `declarative_base` import to `sqlalchemy.orm.declarative_base`.
- Add migration support (Alembic) to avoid manual DB reset on schema changes.
- Add CI workflow for tests (`pytest`) and basic linting.
- Add minimal rate-limiting on auth endpoints.
- Add production `.env` template with secure defaults and secret management notes.

## Notes

- This project is educational and demonstrates core KMS + IAM concepts.
- Do not use development defaults (example secrets/passwords) in production.

