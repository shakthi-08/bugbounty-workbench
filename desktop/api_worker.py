"""Qt worker wrapper for non-blocking API requests."""

from PySide6.QtCore import QObject, QRunnable, Signal, Slot


class ApiWorkerSignals(QObject):
    succeeded = Signal(str, object)
    failed = Signal(str, str)
    finished = Signal(object)


class ApiWorker(QRunnable):
    def __init__(self, api_client, key: str, path: str, method: str = "GET", payload=None):
        super().__init__()
        self.api_client = api_client
        self.key = key
        self.path = path
        self.method = method
        self.payload = payload
        self.signals = ApiWorkerSignals()

    @Slot()
    def run(self):
        try:
            if self.key.startswith("report_export_") and hasattr(self.api_client, "request_text"):
                result = self.api_client.request_text(self.method, self.path)
            else:
                result = self.api_client.request_json(self.method, self.path, self.payload)
            self.signals.succeeded.emit(self.key, result)
        except Exception as error:
            self.signals.failed.emit(self.key, str(error))
        finally:
            self.signals.finished.emit(self)
