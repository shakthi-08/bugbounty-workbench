from PySide6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem

from .base import BaseView
from ..widgets.empty_state import EmptyState


class CollectionView(BaseView):
    def __init__(self, title: str, subtitle: str, columns: list[tuple[str, str]], empty_text: str, parent=None):
        super().__init__(title, subtitle, parent)
        self.columns = columns
        self.empty_state = EmptyState(empty_text)
        self.table = QTableWidget(0, len(columns))
        self.table.setHorizontalHeaderLabels([label for label, _ in columns])
        self.table.setObjectName("dataTable")
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.layout.addWidget(self.empty_state, 1)
        self.layout.addWidget(self.table, 1)
        self.set_items([])

    def set_items(self, rows: list[dict]):
        rows = rows if isinstance(rows, list) else []
        self.table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for column_index, (_, key) in enumerate(self.columns):
                value = row.get(key)
                if key == "included":
                    value = "Included" if value else "Excluded"
                elif value is None or value == "":
                    value = "—"
                item = QTableWidgetItem(str(value))
                self.table.setItem(row_index, column_index, item)
        has_rows = bool(rows)
        self.empty_state.setVisible(not has_rows)
        self.table.setVisible(has_rows)
