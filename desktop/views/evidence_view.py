from PySide6.QtWidgets import QTextBrowser, QVBoxLayout

from .collection_view import CollectionView


class EvidenceView(CollectionView):
    def __init__(self, parent=None):
        self.rows = []
        super().__init__("Evidence", "Sanitized evidence stored for the selected project.",
                         [("ID", "id"), ("Type", "evidence_type"), ("Title", "title"),
                          ("Finding", "finding_id"), ("Result", "result_id"),
                          ("Created", "created_at")],
                         "No evidence has been recorded for this project.", parent)
        self.details = QTextBrowser()
        self.details.setOpenExternalLinks(False)
        self.details.setMaximumHeight(160)
        self.layout.addWidget(self.details)
        self.table.itemSelectionChanged.connect(self._show_selected)

    def set_items(self, rows):
        self.rows = rows if isinstance(rows, list) else []
        super().set_items(self.rows)
        if hasattr(self, "details"):
            self.details.clear()

    def _show_selected(self):
        row = self.table.currentRow()
        if 0 <= row < len(self.rows):
            item = self.rows[row]
            metadata = item.get("metadata", {})
            self.details.setPlainText(
                f"{item.get('description') or ''}\n\n"
                f"Reference: {item.get('path_reference') or '—'}\n"
                f"Content hash: {item.get('content_hash') or '—'}\n"
                f"Metadata: {metadata}"
            )
