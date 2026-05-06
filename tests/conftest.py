from typing import Callable, Dict

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.main import app
from app.api import keys as keys_api
from app import models as _models  # noqa: F401 - ensures model metadata is registered


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
def client(db_session_factory):
	def override_get_db():
		db = db_session_factory()
		try:
			yield db
		finally:
			db.close()

	app.dependency_overrides[keys_api.get_db] = override_get_db
	with TestClient(app) as test_client:
		yield test_client
	app.dependency_overrides.clear()


@pytest.fixture()
def override_current_user() -> Callable[[Dict], None]:
	def _set_user(user_payload: Dict):
		def _override_user():
			return user_payload

		app.dependency_overrides[keys_api.get_current_user] = _override_user

	return _set_user


