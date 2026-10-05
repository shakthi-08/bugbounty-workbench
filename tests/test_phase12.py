import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from alembic.config import Config
from alembic.script import ScriptDirectory
from app.core.config import get_data_dir
from app.api.assessments import _filename
from app.main import app


class Phase12ConfigurationAndMigrationTests(unittest.TestCase):
    def test_data_directory_defaults_and_paths_with_spaces(self):
        default = get_data_dir({"LOCALAPPDATA": r"C:\Local App Data"})
        self.assertEqual(default, Path(r"C:\Local App Data") / "BugBountyWorkbench")
        with tempfile.TemporaryDirectory(prefix="workbench path ") as temp:
            configured = Path(temp) / "user data with spaces"
            resolved = get_data_dir({"BUGBOUNTY_DATA_DIR": str(configured), "LOCALAPPDATA": "ignored"})
            self.assertEqual(resolved, configured.resolve())
            self.assertFalse(resolved.exists(), "Path resolution must not create directories as a side effect.")

    def test_relative_data_directory_is_backend_relative_and_safe_for_missing_directory(self):
        resolved = get_data_dir({"BUGBOUNTY_DATA_DIR": "missing data folder"})
        self.assertEqual(resolved, (BACKEND / "missing data folder").resolve())
        self.assertFalse(resolved.exists())

    def test_migration_chain_is_single_and_ends_at_expected_head(self):
        config = Config(str(BACKEND / "alembic.ini"))
        scripts = ScriptDirectory.from_config(config)
        self.assertEqual(scripts.get_heads(), ["c73f9a21d604"])
        revisions = list(scripts.walk_revisions())
        ids = [revision.revision for revision in revisions]
        self.assertEqual(len(ids), len(set(ids)))

    def test_safe_export_filename_and_no_generic_execution_routes(self):
        class AssessmentName:
            id = 42
            name = '../../report"\r\nInjected: value'
        filename = _filename(AssessmentName(), "html")
        self.assertEqual(filename, "assessment_42_report_Injected_value.html")
        paths = set(app.openapi()["paths"])
        self.assertNotIn("/scan", paths)
        self.assertFalse(any("/commands" in path or "/shell" in path for path in paths))
        self.assertTrue(any(path.endswith("/assessments/{assessment_id}/export/html") for path in paths))

    def test_fresh_database_migrates_to_head_inside_path_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix="Phase 12 migration ") as temp:
            data_dir = Path(temp) / "new workbench database"
            environment = os.environ.copy()
            environment["BUGBOUNTY_DATA_DIR"] = str(data_dir)
            completed = subprocess.run(
                [sys.executable, "-m", "alembic", "-c", str(BACKEND / "alembic.ini"), "upgrade", "head"],
                cwd=BACKEND, env=environment, capture_output=True, text=True, timeout=60, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            database = data_dir / "bugbounty.db"
            self.assertTrue(database.is_file())
            connection = sqlite3.connect(database)
            try:
                revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                connection.close()
            self.assertEqual(revision, "c73f9a21d604")
            self.assertTrue({"projects", "assessments", "findings", "evidence", "security_audit_logs"} <= tables)


if __name__ == "__main__":
    unittest.main()
