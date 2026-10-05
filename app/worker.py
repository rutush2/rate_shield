import asyncio
import json
import os
import sqlite3
import time
from ollama import AsyncClient

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "telemetry.db")

audit_queue = asyncio.Queue()


def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def normalize_categories(raw_categories):
    mapping = {
        "sql injection": "sqli",
        "sql_injection": "sqli",
        "sqlinjection": "sqli",
        "sql": "sqli",
        "xss_attack": "xss",
        "cross_site_scripting": "xss",
        "cross-site scripting": "xss",
        "command_injection": "cmdi",
        "command injection": "cmdi",
        "cmd_injection": "cmdi",
    }

    if not isinstance(raw_categories, list):
        raw_categories = [str(raw_categories)]

    cleaned = []
    for cat in raw_categories:
        c = str(cat).lower().strip()
        c_mapped = mapping.get(c, c)
        if c_mapped in ["sqli", "xss", "cmdi", "none"]:
            cleaned.append(c_mapped)
        else:
            cleaned.append("other")

    return list(set(cleaned)) if cleaned else ["none"]


async def process_audit_queue(queue: asyncio.Queue):
    client = AsyncClient()

    while True:
        item = await queue.get()
        telemetry_id = item.get("telemetry_id")
        payload_sample = item.get("payload_sample")

        start_time = time.time()

        system_prompt = """
        You are a security auditor analyzing HTTP payload queries.
        Classify the payload and return STRICT JSON with these exact keys:
        - threat_score: integer (0-100)
        - remediation_action: string ("ALLOW", "SANITIZE", or "BLOCK")
        - flagged_categories: list of strings, MUST ONLY use items from: ["sqli", "xss", "cmdi", "none"]
        """

        try:
            response = await client.chat(
                model="llama3",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Payload: {payload_sample}"},
                ],
                format="json",
            )

            raw_output = response.get("message", {}).get("content", "{}")
            llm_data = json.loads(raw_output)

            raw_score = llm_data.get("threat_score", 0)
            try:
                threat_score = int(raw_score)
            except (ValueError, TypeError):
                threat_score = 0

            if threat_score >= 70:
                remediation_action = "BLOCK"
            elif threat_score >= 30:
                remediation_action = "SANITIZE"
            else:
                remediation_action = "ALLOW"

            raw_categories = llm_data.get("flagged_categories", ["none"])
            flagged_categories = json.dumps(normalize_categories(raw_categories))

        except Exception as e:
            threat_score = -1
            remediation_action = "ALLOW"
            flagged_categories = json.dumps(["inspection_error"])
            raw_output = str(e)

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        def write_to_db():
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO security_audits (
                    telemetry_id,
                    payload_sample,
                    threat_score,
                    flagged_categories,
                    remediation_action,
                    inspection_time_ms,
                    raw_llm_output
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    telemetry_id,
                    payload_sample,
                    threat_score,
                    flagged_categories,
                    remediation_action,
                    elapsed_ms,
                    raw_output,
                ),
            )
            conn.commit()
            conn.close()

        await asyncio.to_thread(write_to_db)
        queue.task_done()