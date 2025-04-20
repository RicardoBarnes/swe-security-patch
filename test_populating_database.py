import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

# Assuming models and functions are available to import
from models import Base, Application, PatchHistory
import backend.populating_database as pd

# --- SETUP ---

@pytest.fixture(scope="function")
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = scoped_session(sessionmaker(bind=engine))
    pd.session = Session()  # Inject into module under test
    yield pd.session
    Session.remove()


# --- MOCK WINGET OUTPUT ---

WINGET_UPGRADE_OUTPUT = """\
Name                          Id                       Version        Available     Source
FakeApp                       com.fake.app            1.0            2.0           winget
Another App                   com.example.app         3.5            4.0           winget
"""

WINGET_LIST_OUTPUT = """\
Name                          Version
FakeApp                       2.0
Another App                   3.5
"""

# --- TESTS ---

@patch("backend.populating_database.subprocess.run")
def test_get_upgradable_apps_parses_correctly(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout=WINGET_UPGRADE_OUTPUT)
    apps = pd.get_upgradable_apps()
    assert len(apps) == 2
    assert apps[0]["name"] == "FakeApp"
    assert apps[0]["id"] == "com.fake.app"
    assert apps[0]["installed"] == "1.0"
    assert apps[0]["available"] == "2.0"


@patch("backend.populating_database.get_upgradable_apps")
def test_save_apps_to_db_inserts_and_logs_patch(mock_get_apps, db_session):
    mock_get_apps.return_value = [{
        "name": "FakeApp",
        "id": "com.fake.app",
        "installed": "1.0",
        "available": "2.0"
    }]

    pd.save_apps_to_db()

    app = db_session.query(Application).filter_by(package_identifier="com.fake.app").first()
    assert app is not None
    assert app.available_update == "2.0"

    patch = db_session.query(PatchHistory).filter_by(app_id=app.app_id).first()
    assert patch is not None
    assert patch.status == "pending"


def test_log_patch_history_prevents_duplicates(db_session):
    app = Application(
        app_name="FakeApp",
        package_identifier="com.fake.app",
        current_version="1.0",
        available_update="2.0",
        last_checked=datetime.utcnow()
    )
    db_session.add(app)
    db_session.commit()

    pd.log_patch_history(app.app_id, "2.0")
    pd.log_patch_history(app.app_id, "2.0")  # Should not duplicate

    patches = db_session.query(PatchHistory).filter_by(app_id=app.app_id).all()
    assert len(patches) == 1


@patch("backend.populating_database.subprocess.run")
def test_detect_applied_updates_marks_success(mock_run, db_session):
    mock_run.return_value = MagicMock(returncode=0, stdout=WINGET_LIST_OUTPUT)

    app = Application(
        app_name="FakeApp",
        package_identifier="com.fake.app",
        current_version="1.0",
        available_update="2.0",
        last_checked=datetime.utcnow()
    )
    db_session.add(app)
    db_session.commit()

    patch = PatchHistory(
        app_id=app.app_id,
        patch_version="2.0",
        status="pending"
    )
    db_session.add(patch)
    db_session.commit()

    pd.detect_applied_updates()

    updated_patch = db_session.query(PatchHistory).filter_by(app_id=app.app_id).first()
    assert updated_patch.status == "success"
    assert updated_patch.installed_on is not None
