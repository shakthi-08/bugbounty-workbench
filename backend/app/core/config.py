import os
from pathlib import Path
from typing import Mapping


BACKEND_DIR = Path(__file__).resolve().parents[2]
DATA_DIR_ENV = "BUGBOUNTY_DATA_DIR"


def get_data_dir(environ: Mapping[str, str] | None = None) -> Path:
    """Return the configured data directory, independent of the working directory."""
    env = os.environ if environ is None else environ

    configured_dir = env.get(DATA_DIR_ENV)
    if configured_dir:
        path = Path(configured_dir).expanduser()
        if not path.is_absolute():
            path = BACKEND_DIR / path
        return path.resolve()

    local_app_data = env.get("LOCALAPPDATA")
    if local_app_data:
        base_dir = Path(local_app_data).expanduser()
    else:
        # Keep non-Windows development predictable when LOCALAPPDATA is absent.
        base_dir = Path.home() / "AppData" / "Local"

    return (base_dir / "BugBountyWorkbench").resolve()
