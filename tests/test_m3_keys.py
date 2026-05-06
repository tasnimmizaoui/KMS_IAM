import json

from app.models.key import Key


def test_create_key_without_token_returns_401(client):
    response = client.post(
        "/keys/create",
        json={"name": "m3-no-token", "allowed_ops": ["encrypt", "decrypt"], "rotation_days": 90},
    )

    assert response.status_code == 401


def test_create_key_with_invalid_allowed_ops_returns_400(client, override_current_user):
    override_current_user({"id": "user-km-1", "username": "km", "roles": ["key_manager"]})

    response = client.post(
        "/keys/create",
        json={"name": "m3-invalid-ops", "allowed_ops": ["encrypt", "sign"], "rotation_days": 90},
    )

    assert response.status_code == 400
    assert "allowed_ops" in response.json()["detail"]


def test_rotate_missing_key_returns_404(client, override_current_user):
    override_current_user({"id": "user-km-2", "username": "km2", "roles": ["key_manager"]})

    response = client.post("/keys/not-a-real-key-id/rotate")

    assert response.status_code == 404


def test_rotate_with_key_user_returns_403(client, override_current_user):
    override_current_user({"id": "user-km-3", "username": "km3", "roles": ["key_manager"]})
    create_resp = client.post(
        "/keys/create",
        json={"name": "m3-forbidden-rotate", "allowed_ops": ["encrypt", "decrypt"], "rotation_days": 90},
    )
    assert create_resp.status_code == 200
    key_id = create_resp.json()["id"]

    override_current_user({"id": "user-ku-1", "username": "ku", "roles": ["key_user"]})
    rotate_resp = client.post(f"/keys/{key_id}/rotate")

    assert rotate_resp.status_code == 403


def test_rotate_disabled_key_returns_400(client, override_current_user, db_session_factory):
    override_current_user({"id": "user-km-4", "username": "km4", "roles": ["key_manager"]})
    create_resp = client.post(
        "/keys/create",
        json={"name": "m3-disabled-state", "allowed_ops": ["encrypt", "decrypt"], "rotation_days": 90},
    )
    assert create_resp.status_code == 200
    key_id = create_resp.json()["id"]

    db = db_session_factory()
    try:
        key_row = db.query(Key).filter(Key.id == key_id).first()
        assert key_row is not None
        key_row.state = "disabled"
        db.commit()
    finally:
        db.close()

    rotate_resp = client.post(f"/keys/{key_id}/rotate")

    assert rotate_resp.status_code == 400
    assert "not valid for rotation" in rotate_resp.json()["detail"]


def test_rotate_success_returns_200(client, override_current_user, db_session_factory):
    override_current_user({"id": "user-km-5", "username": "km5", "roles": ["key_manager"]})
    create_resp = client.post(
        "/keys/create",
        json={"name": "m3-rotate-ok", "allowed_ops": ["encrypt", "decrypt"], "rotation_days": 90},
    )
    assert create_resp.status_code == 200
    key_id = create_resp.json()["id"]

    rotate_resp = client.post(f"/keys/{key_id}/rotate")
    assert rotate_resp.status_code == 200

    payload = rotate_resp.json()
    assert payload["old_key_id"] == key_id
    assert payload["new_key_id"]
    assert payload["new_version"] == 2

    db = db_session_factory()
    try:
        old_key = db.query(Key).filter(Key.id == key_id).first()
        new_key = db.query(Key).filter(Key.id == payload["new_key_id"]).first()
        assert old_key is not None
        assert new_key is not None

        old_ops = json.loads(old_key.allowed_ops or "[]")
        assert "encrypt" not in old_ops
        assert "decrypt" in old_ops
    finally:
        db.close()

