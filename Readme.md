# Cryptographic Key Management System (KMS) with Mini-IAM

## Project Overview

This project implements a **Cryptographic Key Management System** integrated with a **Mini Identity & Access Management (IAM)** service for a private cloud environment. It provides secure generation, storage, and usage of cryptographic keys with role-based access control.

**Key concepts demonstrated:**
- **Envelope encryption** (DEK wrapped by KEK)
- **AES-256-GCM** authenticated encryption
- **JWT authentication** with bcrypt password hashing
- **RBAC** (admin, key_manager, key_user)
- **Key rotation** and versioning
- **REST API** with automatic OpenAPI documentation

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Client (curl / Swagger)                  │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTPS / HTTP
┌─────────────────────────▼───────────────────────────────────┐
│                    FastAPI (port 8000)                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ /auth/*      │  │ /keys/*      │  │ /docs        │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                    Business Logic                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ IAM Manager  │  │ Key Manager  │  │ Crypto Core  │      │
│  │ • Users      │  │ • Create     │  │ • AES-256    │      │
│  │ • JWT        │  │ • Encrypt    │  │ • Envelope   │      │
│  │ • Roles      │  │ • Decrypt    │  │ • Master Key │      │
│  │ • Policies   │  │ • Rotate     │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                    Storage Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ SQLite DB    │  │ Master Key   │  │ Key Material │      │
│  │ (metadata)   │  │ (file)       │  │ (encrypted)  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

---

## Features Implemented

### ✅ Identity & Access Management (IAM)
- User registration with bcrypt password hashing
- JWT-based authentication (HS256, 1-hour expiry)
- Role management: `admin`, `key_manager`, `key_user`
- Role assignment (admin only)
- RBAC policy engine (who can perform which actions)

### ✅ Cryptographic Key Management (KMS)
- **AES-256-GCM** key generation
- Envelope encryption: Data Encryption Key (DEK) encrypted by Master Key (KEK)
- Master key stored separately (simulated HSM)
- Encrypt / decrypt operations using stored keys
- Key rotation (new version created, old version disabled for encryption)
- List keys (metadata only, no key material exposure)

### ✅ REST API
- Automatic OpenAPI (Swagger) documentation at `/docs`
- Bearer token authentication for protected endpoints
- Input validation with Pydantic

### ✅ Database
- SQLite with SQLAlchemy ORM
- Tables: users, roles, user_roles, keys
- Keys stored as encrypted JSON blobs (envelope format)

---

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Create new user account |
| POST | `/auth/login` | Authenticate and receive JWT token |
| POST | `/auth/assign-role` | Assign role to user (admin only) |

### Key Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/keys/create` | Generate a new AES-256 key |
| GET | `/keys/` | List all keys (metadata) |
| POST | `/keys/encrypt` | Encrypt data with a specified key |
| POST | `/keys/decrypt` | Decrypt data with a specified key |
| POST | `/keys/{key_id}/rotate` | Rotate key (new version) |

### Utility

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/` | API information |
| GET | `/docs` | Swagger UI documentation |

---

## Installation & Setup

### Prerequisites
- Python 3.11+
- pip

### Steps

```bash
# Clone or download the project
cd kms-iam

# Create virtual environment
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

# Install dependencies
pip install fastapi uvicorn sqlalchemy cryptography bcrypt pyjwt python-dotenv

# Initialize database
python scripts/init_db.py

# Insert default roles
python scripts/init_roles.py

# (Optional) Bootstrap admin user
python -c "
from app.database import SessionLocal
from app.iam.manager import IAMManager
db = SessionLocal()
iam = IAMManager()
iam.create_user(db, 'admin', 'AdminPass123!', 'admin@kms.local')
iam.assign_role(db, 'admin', 'admin')
iam.assign_role(db, 'admin', 'key_manager')
print('Admin user created: admin / AdminPass123!')
db.close()
"

# Start the API server
python3 -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

Open http://localhost:8000/docs in your browser.

---

## Usage Examples

### 1. Register a new user

```bash
curl -X POST "http://localhost:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Alice123!","email":"alice@example.com"}'
```

### 2. Login to get JWT token

```bash
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Alice123!"}'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### 3. Create a cryptographic key

```bash
curl -X POST "http://localhost:8000/keys/create" \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"db-encryption-key","allowed_ops":["encrypt","decrypt"],"rotation_days":90}'
```

### 4. Encrypt data

```bash
# "Hello World" in base64
PLAINTEXT_B64="SGVsbG8gV29ybGQ="

curl -X POST "http://localhost:8000/keys/encrypt" \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d "{\"key_id\":\"<key_id_from_step_3>\",\"plaintext_b64\":\"$PLAINTEXT_B64\"}"
```

Response:
```json
{
  "ciphertext_b64": "xK3...",
  "iv_b64": "abc...",
  "tag_b64": "def..."
}
```

### 5. Decrypt data

```bash
curl -X POST "http://localhost:8000/keys/decrypt" \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{"key_id":"<key_id>","ciphertext_b64":"...","iv_b64":"...","tag_b64":"..."}'
```

### 6. List all keys

```bash
curl -X GET "http://localhost:8000/keys/" \
  -H "Authorization: Bearer <your_token>"
```

### 7. Rotate a key

```bash
curl -X POST "http://localhost:8000/keys/<key_id>/rotate" \
  -H "Authorization: Bearer <your_token>"
```

---
## Smoke test (E2E API)

Prereqs:
- API running on http://localhost:8000
- WSL/bash
- jq installed

Run:
```bash
cd /mnt/c/Users/farah/KMS_IAM
source venv/bin/activate
chmod +x scripts/smoke_api_bootstrap.sh
BASE_URL="http://localhost:8000" ./scripts/smoke_api_bootstrap.sh
```

## Security Model

| Component | Implementation |
|-----------|----------------|
| **Password storage** | bcrypt (salt + hash) |
| **Authentication** | JWT (HS256, 1-hour expiry) |
| **Data encryption** | AES-256-GCM (authenticated) |
| **Key protection** | Envelope encryption (DEK wrapped by KEK) |
| **Master key** | Stored in a file with 0o600 permissions |
| **Database** | Keys stored as encrypted blobs (never plaintext) |
| **Access control** | RBAC (admin, key_manager, key_user) |

### Role Permissions

| Action | admin | key_manager | key_user |
|--------|-------|-------------|----------|
| Create keys | ✅ | ✅ | ❌ |
| Encrypt data | ✅ | ✅ | ✅ |
| Decrypt data | ✅ | ✅ | ✅ |
| Rotate keys | ✅ | ✅ | ❌ |
| List keys | ✅ | ✅ | ✅ |
| Assign roles | ✅ | ❌ | ❌ |

---

## Project Structure

```
kms-iam/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # Settings from .env
│   ├── database.py          # SQLAlchemy setup
│   ├── models/
│   │   ├── user.py
│   │   ├── role.py
│   │   └── key.py
│   ├── iam/
│   │   ├── manager.py       # User & JWT logic
│   │   └── policy.py        # RBAC rules
│   ├── kms/
│   │   └── key_manager.py   # Key lifecycle
│   ├── crypto/
│   │   └── core.py          # AES & envelope encryption
│   └── api/
│       ├── auth.py          # /auth endpoints
│       └── keys.py          # /keys endpoints
├── scripts/
│   ├── init_db.py           # Create tables
│   └── init_roles.py        # Insert default roles
├── data/                    # Persistent data (SQLite, master.key)
├── .env                     # Configuration
└── requirements.txt
```

---

## Default Test Credentials

After bootstrapping (see Setup section), you can use:

| Username | Password | Roles |
|----------|----------|-------|
| admin | AdminPass123! | admin, key_manager |
| alice | Alice123! | *(assign role via admin)* |

---

## Future Improvements (Optional)

- ✅ Audit logging (track every operation)
- ✅ Key auto-rotation based on expiration
- ✅ Rate limiting
- ✅ Prometheus metrics
- ✅ CLI tool
- ✅ PostgreSQL support

---

## License

This project is for educational purposes as part of a cryptography course.

---

## Recent Improvements

### ✅ Audit Logging on Success Paths
All sensitive operations now log **both failures and successes** to the audit trail:
- `LOGIN` / `LOGIN_FAIL`
- `KEY_CREATE`, `KEY_ENCRYPT`, `KEY_DECRYPT`, `KEY_ROTATE`
- `ROLE_ASSIGN`

Each entry includes timestamp, user ID, action, resource, success status, and source IP.

View logs (admin only):
```bash
GET /audit/logs
GET /audit/stats
```

### ✅ Key Auto-Rotation Scheduler
A background scheduler starts automatically with the server and rotates any key that has exceeded its `rotation_days` threshold — no manual intervention needed.

- Runs every hour
- Logs every rotation to the audit trail as `system-scheduler`
- Confirmation on startup: `[scheduler] Auto-rotation scheduler started — runs every hour`

To test manually:
```bash
PYTHONPATH=. python3 -c "
from app.scheduler import auto_rotate_expired_keys
auto_rotate_expired_keys()
"
```
