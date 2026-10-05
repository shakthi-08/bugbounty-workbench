from PySide6.QtWidgets import QLabel


class StatusPill(QLabel):
    def __init__(self, text: str = "Checking backend", parent=None):
        super().__init__(text, parent)
        self.setObjectName("statusPill")
        self.set_connected(False)

    def set_connected(self, connected: bool, detail: str | None = None):
        self.setProperty("connected", connected)
        self.setText(detail or ("Connected" if connected else "Offline"))
        self.style().unpolish(self)
        self.style().polish(self)
