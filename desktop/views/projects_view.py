from PySide6.QtCore import Signal
from PySide6.QtWidgets import QComboBox, QLabel, QFrame, QVBoxLayout

from .base import BaseView
from ..widgets.empty_state import EmptyState


class ProjectsView(BaseView):
    project_selected = Signal(int)

    def __init__(self, parent=None):
        super().__init__("Projects", "Choose the project whose local assessment data you want to view.", parent)
        self.selector = QComboBox()
        self.selector.setMinimumHeight(40)
        self.selector.currentIndexChanged.connect(self._selection_changed)
        self.layout.addWidget(self.selector)

        self.details = QFrame()
        self.details.setObjectName("detailCard")
        details_layout = QVBoxLayout(self.details)
        self.name_label = QLabel("No projects loaded")
        self.name_label.setObjectName("cardTitle")
        self.description_label = QLabel("Refresh to load projects from the local API.")
        self.description_label.setObjectName("viewSubtitle")
        self.description_label.setWordWrap(True)
        details_layout.addWidget(self.name_label)
        details_layout.addWidget(self.description_label)
        self.layout.addWidget(self.details)
        self.empty_state = EmptyState("No projects were returned by the backend.")
        self.layout.addWidget(self.empty_state)
        self.layout.addStretch(1)
        self.projects = []

    def set_projects(self, projects: list[dict], selected_id: int | None = None):
        self.projects = projects
        self.selector.blockSignals(True)
        self.selector.clear()
        for project in projects:
            self.selector.addItem(project.get("name", "Unnamed project"), project.get("id"))
        index = next(
            (i for i, project in enumerate(projects) if project.get("id") == selected_id),
            0 if projects else -1,
        )
        self.selector.setCurrentIndex(index)
        self.selector.blockSignals(False)
        self.empty_state.setVisible(not projects)
        self.details.setVisible(bool(projects))
        self.selector.setVisible(bool(projects))
        if index >= 0:
            self._show_project(projects[index])

    def _selection_changed(self, index: int):
        if index < 0 or index >= len(self.projects):
            return
        project = self.projects[index]
        self._show_project(project)
        project_id = project.get("id")
        if isinstance(project_id, int):
            self.project_selected.emit(project_id)

    def _show_project(self, project: dict):
        self.name_label.setText(project.get("name") or "Unnamed project")
        self.description_label.setText(project.get("description") or "No description provided.")

    def selected_project_id(self) -> int | None:
        value = self.selector.currentData()
        return value if isinstance(value, int) else None
