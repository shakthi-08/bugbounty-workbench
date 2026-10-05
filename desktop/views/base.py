from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


class BaseView(QWidget):
    def __init__(self, title: str, subtitle: str = "", parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(28, 24, 28, 28)
        self.layout.setSpacing(18)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("viewTitle")
        self.layout.addWidget(self.title_label)

        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setObjectName("viewSubtitle")
            subtitle_label.setWordWrap(True)
            self.layout.addWidget(subtitle_label)

    def set_error(self, message: str | None):
        if not hasattr(self, "error_label"):
            self.error_label = QLabel()
            self.error_label.setObjectName("inlineError")
            self.error_label.setWordWrap(True)
            self.layout.insertWidget(2, self.error_label)
        self.error_label.setText(message or "")
        self.error_label.setVisible(bool(message))
