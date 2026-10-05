from contextlib import asynccontextmanager
import asyncio
import os
import sqlite3
from typing import Dict, Any
from fastapi import FastAPI
from pydantic import BaseModel
from app.middleware import TelemetryMiddleware
from app.worker import process_audit_queue, audit_queue

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "telemetry.db")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS request_telemetry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_ip TEXT,
        endpoint TEXT,
        http_method TEXT,
        status_code INTEGER,
        response_time_ms REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_audits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telemetry_id INTEGER,
        payload_sample TEXT,
        threat_score INTEGER,
        flagged_categories TEXT,
        remediation_action TEXT,
        inspection_time_ms REAL,
        raw_llm_output TEXT,
        analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(telemetry_id) REFERENCES request_telemetry(id)
    );
    """)
    conn.commit()
    conn.close()


class IngestPayload(BaseModel):
    user_id: str
    query: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    worker_task = asyncio.create_task(process_audit_queue(audit_queue))
    yield
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Rate Shield API", lifespan=lifespan)
app.add_middleware(TelemetryMiddleware)


@app.get("/health")
async def health_check() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/ingest")
async def ingest_data(payload: IngestPayload) -> Dict[str, Any]:
    return {"status": "received", "data": payload.model_dump()}