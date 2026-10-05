"""Reject oversized API request bodies before JSON parsing or persistence."""

import json


class RequestBodyLimitMiddleware:
    def __init__(self, app, max_request_bytes: int = 2 * 1024 * 1024):
        self.app = app
        self.max_request_bytes = max_request_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                if int(raw_length) > self.max_request_bytes:
                    await self._too_large(send)
                    return
            except ValueError:
                await self._bad_length(send)
                return

        chunks = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.max_request_bytes:
                await self._too_large(send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay, send)

    async def _too_large(self, send):
        await self._respond(send, 413, "Request body exceeds the 2 MiB limit.")

    async def _bad_length(self, send):
        await self._respond(send, 400, "Invalid Content-Length header.")

    @staticmethod
    async def _respond(send, status, detail):
        body = json.dumps({"detail": detail}).encode("utf-8")
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode("ascii"))]})
        await send({"type": "http.response.body", "body": body})
