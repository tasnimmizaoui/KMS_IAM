import base64

from app.audit.logger import AuditLogger


def test_forbidden_create_is_audited(client, override_current_user):
    override_current_user({"id": "u-key-user", "username": "bob", "roles": ["key_user"]})

    response = client.post(
        "/keys/create",
        json={"name": "m4-deny", "allowed_ops": ["encrypt", "decrypt"], "rotation_days": 90},
    )

    assert response.status_code == 403

    logs = AuditLogger.get_logs(limit=50, action="KEY_CREATE")
    assert logs
    assert logs[0]["success"] is False
    assert logs[0]["user_id"] == "u-key-user"
    assert logs[0]["details"]["reason"] == "insufficient_role"


def test_forbidden_rotate_is_audited(client, override_current_user):
    override_current_user({"id": "u-km", "username": "alice", "roles": ["key_manager"]})
    create_resp = client.post(
        "/keys/create",
        json={"name": "m4-rotate-target", "allowed_ops": ["encrypt", "decrypt"], "rotation_days": 90},
    )
    assert create_resp.status_code == 200
    key_id = create_resp.json()["id"]

    override_current_user({"id": "u-ku", "username": "bob", "roles": ["key_user"]})
    rotate_resp = client.post(f"/keys/{key_id}/rotate")

    assert rotate_resp.status_code == 403

    logs = AuditLogger.get_logs(limit=50, action="KEY_ROTATE")
    assert logs
    assert logs[0]["success"] is False
    assert logs[0]["resource_id"] == key_id


def test_audit_logs_endpoint_admin_only_and_traced(client, override_current_user):
    override_current_user({"id": "u-ku2", "username": "bob", "roles": ["key_user"]})
    forbidden = client.get("/audit/logs")

    assert forbidden.status_code == 403

    deny_logs = AuditLogger.get_logs(limit=50, action="AUDIT_LOGS_READ")
    assert deny_logs
    assert deny_logs[0]["success"] is False
    assert deny_logs[0]["details"]["reason"] == "insufficient_role"

    override_current_user({"id": "u-admin", "username": "admin", "roles": ["admin"]})
    allowed = client.get("/audit/logs?limit=20")

    assert allowed.status_code == 200
    payload = allowed.json()
    assert "logs" in payload and "count" in payload

    read_logs = AuditLogger.get_logs(limit=50, action="AUDIT_LOGS_READ")
    assert any(entry["success"] is True for entry in read_logs)


def test_forbidden_encrypt_is_audited(client, override_current_user):
    override_current_user({"id": "u-km2", "username": "alice", "roles": ["key_manager"]})
    create_resp = client.post(
        "/keys/create",
        json={"name": "m4-encrypt-target", "allowed_ops": ["encrypt", "decrypt"], "rotation_days": 90},
    )
    assert create_resp.status_code == 200
    key_id = create_resp.json()["id"]

    plaintext_b64 = base64.b64encode(b"hello").decode()

    override_current_user({"id": "u-none", "username": "eve", "roles": []})
    deny = client.post(
        "/keys/encrypt",
        json={"key_id": key_id, "plaintext_b64": plaintext_b64},
    )

    assert deny.status_code == 403
    logs = AuditLogger.get_logs(limit=50, action="KEY_ENCRYPT")
    assert logs
    assert logs[0]["success"] is False
    assert logs[0]["resource_id"] == key_id

