import os
import asyncio
import gc
import sqlite3
import sys
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4


BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

# Isolate the API integration tests from the user's real project database.
_TEST_DATA = tempfile.TemporaryDirectory(
    prefix="bugbounty-workbench-tests-",
    ignore_cleanup_errors=True,
)
os.environ["BUGBOUNTY_DATA_DIR"] = _TEST_DATA.name

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from httpx import ASGITransport, AsyncClient

from app.core.config import get_data_dir
from app.core.database import DATABASE_PATH, EXPECTED_SCHEMA_REVISION
from app.core.database import engine
from app.main import app


ALEMBIC_CONFIG_PATH = BACKEND_DIR / "alembic.ini"
ALEMBIC_CONFIG = Config(str(ALEMBIC_CONFIG_PATH))
command.upgrade(ALEMBIC_CONFIG, "head")


def tearDownModule():
    asyncio.run(engine.dispose())
    gc.collect()
    _TEST_DATA.cleanup()


class DatabaseConfigurationTests(unittest.TestCase):
    def test_data_directory_uses_local_app_data_by_default(self):
        data_dir = get_data_dir({"LOCALAPPDATA": r"C:\Users\Example\AppData\Local"})

        self.assertEqual(
            data_dir,
            Path(r"C:\Users\Example\AppData\Local") / "BugBountyWorkbench",
        )

    def test_explicit_data_directory_is_independent_of_working_directory(self):
        configured = Path(_TEST_DATA.name) / "explicit-location"

        self.assertEqual(
            get_data_dir({"BUGBOUNTY_DATA_DIR": str(configured)}),
            configured.resolve(),
        )

    def test_runtime_database_uses_configured_directory(self):
        self.assertEqual(
            DATABASE_PATH.resolve(),
            (Path(_TEST_DATA.name) / "bugbounty.db").resolve(),
        )
        self.assertTrue(DATABASE_PATH.is_file())


class MigrationTests(unittest.TestCase):
    def test_alembic_has_a_current_schema_revision(self):
        scripts = ScriptDirectory.from_config(ALEMBIC_CONFIG)

        self.assertEqual(scripts.get_current_head(), EXPECTED_SCHEMA_REVISION)

    def test_migration_creates_all_current_tables_and_version(self):
        connection = sqlite3.connect(DATABASE_PATH)
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            revision = connection.execute(
                "SELECT version_num FROM alembic_version"
            ).fetchone()[0]
        finally:
            connection.close()

        self.assertTrue({"projects", "scopes", "assets", "findings"} <= tables)
        self.assertEqual(revision, EXPECTED_SCHEMA_REVISION)


@asynccontextmanager
async def api_client():
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client


class ApplicationApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_rejects_a_database_without_the_current_migration(self):
        connection = sqlite3.connect(DATABASE_PATH)
        try:
            connection.execute(
                "UPDATE alembic_version SET version_num = ?",
                ("unapplied_revision",),
            )
            connection.commit()

            with self.assertRaisesRegex(RuntimeError, "expected"):
                async with app.router.lifespan_context(app):
                    pass
        finally:
            connection.execute(
                "UPDATE alembic_version SET version_num = ?",
                (EXPECTED_SCHEMA_REVISION,),
            )
            connection.commit()
            connection.close()

    async def test_startup_root_and_health(self):
        async with api_client() as client:
            root = await client.get("/")
            health = await client.get("/health")

        self.assertEqual(root.status_code, 200)
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["status"], "healthy")

    async def test_project_create_and_list(self):
        project_name = f"Project {uuid4()}"

        async with api_client() as client:
            created = await client.post(
                "/projects",
                json={"name": project_name, "description": "API test project"},
            )
            listed = await client.get("/projects")

        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertIn(created.json()["id"], [row["id"] for row in listed.json()])

    async def test_scope_create_list_and_scope_check(self):
        async with api_client() as client:
            project = await client.post("/projects", json={"name": f"Scope {uuid4()}"})
            project_id = project.json()["id"]
            created_scope = await client.post(
                f"/projects/{project_id}/scopes",
                json={"value": "example.test", "scope_type": "domain"},
            )
            scopes = await client.get(f"/projects/{project_id}/scopes")
            decision = await client.post(
                f"/projects/{project_id}/scope-check",
                json={"target": "api.example.test"},
            )

        self.assertEqual(created_scope.status_code, 201, created_scope.text)
        self.assertEqual(scopes.status_code, 200, scopes.text)
        self.assertTrue(any(row["id"] == created_scope.json()["id"] for row in scopes.json()))
        self.assertEqual(decision.status_code, 200, decision.text)
        self.assertTrue(decision.json()["allowed"])

    async def test_asset_create_and_list(self):
        async with api_client() as client:
            project = await client.post("/projects", json={"name": f"Asset {uuid4()}"})
            project_id = project.json()["id"]
            scope = await client.post(
                f"/projects/{project_id}/scopes",
                json={"value": "example.test", "scope_type": "domain"},
            )
            self.assertEqual(scope.status_code, 201, scope.text)
            created = await client.post(
                f"/projects/{project_id}/assets",
                json={"value": "api.example.test", "asset_type": "subdomain"},
            )
            listed = await client.get(f"/projects/{project_id}/assets")

        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertIn(created.json()["id"], [row["id"] for row in listed.json()])

    async def test_finding_create_list_and_asset_project_validation(self):
        async with api_client() as client:
            project = await client.post("/projects", json={"name": f"Finding {uuid4()}"})
            project_id = project.json()["id"]
            await client.post(
                f"/projects/{project_id}/scopes",
                json={"value": "example.test", "scope_type": "domain"},
            )
            asset = await client.post(
                f"/projects/{project_id}/assets",
                json={"value": "api.example.test", "asset_type": "subdomain"},
            )
            self.assertEqual(asset.status_code, 201, asset.text)
            created = await client.post(
                f"/projects/{project_id}/findings",
                json={
                    "asset_id": asset.json()["id"],
                    "title": "Test finding",
                    "severity": "low",
                    "description": "Created by the API integration test.",
                },
            )
            listed = await client.get(f"/projects/{project_id}/findings")
            invalid_asset = await client.post(
                f"/projects/{project_id}/findings",
                json={
                    "asset_id": 2147483647,
                    "title": "Invalid association",
                    "severity": "low",
                    "description": "This asset does not exist.",
                },
            )

        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertIn(created.json()["id"], [row["id"] for row in listed.json()])
        self.assertEqual(invalid_asset.status_code, 404, invalid_asset.text)


if __name__ == "__main__":
    unittest.main()
