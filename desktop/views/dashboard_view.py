from PySide6.QtWidgets import QGridLayout, QLabel, QPushButton, QFrame, QWidget

from .base import BaseView


class MetricCard(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setObjectName("metricCard")
        layout = QGridLayout(self)
        self.value_label = QLabel("—")
        self.value_label.setObjectName("metricValue")
        self.caption_label = QLabel(title)
        self.caption_label.setObjectName("metricCaption")
        layout.addWidget(self.value_label, 0, 0)
        layout.addWidget(self.caption_label, 1, 0)

    def set_value(self, value):
        self.value_label.setText(str(value))


class DashboardView(BaseView):
    def __init__(self, parent=None):
        super().__init__("Dashboard", "A local overview of your assessment workspace.", parent)
        self.current_project = QLabel("No project selected")
        self.current_project.setObjectName("currentProject")
        self.layout.addWidget(self.current_project)
        self.backend_status = QLabel("Backend connection: checking…")
        self.backend_status.setObjectName("backendStatus")
        self.layout.addWidget(self.backend_status)

        cards = QWidget()
        cards_layout = QGridLayout(cards)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setSpacing(14)
        self.scope_card = MetricCard("Scope entries")
        self.asset_card = MetricCard("Assets")
        self.finding_card = MetricCard("Findings")
        cards_layout.addWidget(self.scope_card, 0, 0)
        cards_layout.addWidget(self.asset_card, 0, 1)
        cards_layout.addWidget(self.finding_card, 0, 2)
        self.layout.addWidget(cards)

        self.refresh_button = QPushButton("Refresh workspace")
        self.refresh_button.setObjectName("primaryButton")
        self.layout.addWidget(self.refresh_button, 0)
        self.layout.addStretch(1)

    def set_project(self, name: str | None):
        self.current_project.setText(
            f"Current project  ·  {name}" if name else "No project selected"
        )

    def set_backend_status(self, connected: bool, detail: str | None = None):
        self.backend_status.setProperty("connected", connected)
        self.backend_status.setText(
            f"Backend connection: {detail or ('Connected' if connected else 'Unavailable')}"
        )
        self.backend_status.style().unpolish(self.backend_status)
        self.backend_status.style().polish(self.backend_status)

    def set_counts(self, scopes: int, assets: int, findings: int):
        self.scope_card.set_value(scopes)
        self.asset_card.set_value(assets)
        self.finding_card.set_value(findings)
