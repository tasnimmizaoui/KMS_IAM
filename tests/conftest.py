from typing import Callable, Dict

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.main import app
from app.api import keys as keys_api
from app.api import audit as audit_api
from app import models as _models  # noqa: F401 - ensures model metadata is registered
from app.config import settings


@pytest.fixture(scope="session")
def test_db_path(tmp_path_factory):
    db_dir = tmp_path_factory.mktemp("db")
    return db_dir / "test-kms-iam.db"


@pytest.fixture(scope="session")
def db_engine(test_db_path):
    engine = create_engine(f"sqlite:///{test_db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture()
def db_session_factory(db_engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=db_engine)


@pytest.fixture()
def isolated_audit_log(tmp_path):
    original = settings.AUDIT_LOG_PATH
    settings.AUDIT_LOG_PATH = str(tmp_path / "audit-test.log")
    yield settings.AUDIT_LOG_PATH
    settings.AUDIT_LOG_PATH = original


@pytest.fixture()
def client(db_session_factory, isolated_audit_log):
    def override_get_db():
        db = db_session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[keys_api.get_db] = override_get_db
    app.dependency_overrides[audit_api.get_current_user] = lambda: {
        "id": "admin-default",
        "username": "admin",
        "roles": ["admin"],
    }

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture()
def override_current_user() -> Callable[[Dict], None]:
    def _set_user(user_payload: Dict):
        def _override_user():
            return user_payload

        app.dependency_overrides[keys_api.get_current_user] = _override_user
        app.dependency_overrides[audit_api.get_current_user] = _override_user

    return _set_user
