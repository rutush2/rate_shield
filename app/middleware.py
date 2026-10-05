import json
import os
import sqlite3
import time
from fastapi import Request
from app.worker import audit_queue

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "telemetry.db")


def log_telemetry(client_ip: str, endpoint: str, http_method: str, status_code: int, response_time_ms: float):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO request_telemetry (client_ip, endpoint, http_method, status_code, response_time_ms)
        VALUES (?, ?, ?, ?, ?)
        """,
        (client_ip, endpoint, http_method, status_code, response_time_ms)
    )
    conn.commit()
    telemetry_id = cursor.lastrowid
    conn.close()
    return telemetry_id


class TelemetryMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in ["/docs", "/openapi.json", "/redoc"]:
            await self.app(scope, receive, send)
            return

        start_time = time.time()

        body_bytes = bytearray()

        async def custom_receive():
            message = await receive()
            if message["type"] == "http.request":
                body_bytes.extend(message.get("body", b""))
            return message

        status_code = 200

        async def custom_send(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 200)
            await send(message)

        await self.app(scope, custom_receive, custom_send)

        duration_ms = round((time.time() - start_time) * 1000, 2)
        client_ip = scope.get("client", ("127.0.0.1", 0))[0]
        method = scope.get("method", "GET")

        try:
            telemetry_id = log_telemetry(client_ip, path, method, status_code, duration_ms)

            if body_bytes:
                try:
                    payload_json = json.loads(body_bytes.decode("utf-8"))
                    payload_sample = str(payload_json.get("query", payload_json))
                    audit_queue.put_nowait({
                        "telemetry_id": telemetry_id,
                        "payload_sample": payload_sample
                    })
                except Exception:
                    pass
        except Exception:
            pass