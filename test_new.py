import unittest
from unittest.mock import patch, MagicMock
import new_database_population  # Replace with the name of your .py file (without .py)

class TestAppSync(unittest.TestCase):

    def test_detect_os(self):
        with patch("platform.system", return_value="Windows"):
            self.assertEqual(new_database_population.detect_os(), "windows")
        with patch("platform.system", return_value="Darwin"):
            self.assertEqual(new_database_population.detect_os(), "mac")
        with patch("platform.system", return_value="Linux"):
            self.assertEqual(new_database_population.detect_os(), "linux")
        with patch("platform.system", return_value="OtherOS"):
            self.assertEqual(new_database_population.detect_os(), "unknown")

    @patch("new_database_population.session")
    def test_sync_to_database(self, mock_session):
        mock_query = MagicMock()
        mock_session.query.return_value.filter_by.return_value.first.return_value = None  # Simulate new app

        installed_apps = {
            "TestApp": "1.0"
        }
        upgrades = {
            "testapp": {
                "pkg_id": "testapp.pkg",
                "available": "2.0",
                "current": "1.0"
            }
        }

        new_database_population.sync_to_database(installed_apps, upgrades)
        self.assertTrue(mock_session.add.called)  # Check if a new app was added
        self.assertTrue(mock_session.commit.called)  # Check if commit was called

    @patch("new_database_population.session")
    def test_sync_existing_app(self, mock_session):
        # Simulate existing app
        mock_app = MagicMock()
        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_app

        installed_apps = {
            "ExistingApp": "2.0"
        }
        upgrades = {
            "existingapp": {
                "pkg_id": "existingapp.pkg",
                "available": "3.0",
                "current": "2.0"
            }
        }

        new_database_population.sync_to_database(installed_apps, upgrades)
        self.assertEqual(mock_app.current_version, "2.0")
        self.assertEqual(mock_app.available_update, "3.0")
        self.assertTrue(mock_session.commit.called)

if __name__ == '__main__':
    unittest.main()
