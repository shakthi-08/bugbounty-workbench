"""Launch the Bug Bounty Workbench Windows desktop application."""

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from .api_client import ApiClient
from .backend_manager import BackendManager
from .views.main_window import MainWindow


def main() -> int:
    application = QApplication(sys.argv)
    application.setApplicationName("Bug Bounty Workbench")
    application.setApplicationVersion("1.0.0")
    application.setOrganizationName("Bug Bounty Workbench")

    api_client = ApiClient()
    backend_manager = BackendManager(api_client)
    window = MainWindow(api_client, backend_manager)

    theme_path = Path(__file__).resolve().parent / "resources" / "theme.qss"
    if theme_path.is_file():
        application.setStyleSheet(theme_path.read_text(encoding="utf-8"))

    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
