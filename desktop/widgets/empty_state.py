from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel


class EmptyState(QLabel):
    def __init__(self, message: str, parent=None):
        super().__init__(message, parent)
        self.setObjectName("emptyState")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setWordWrap(True)
