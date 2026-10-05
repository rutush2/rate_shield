import os
import sqlite3

DB_PATH = os.path.join("data", "telemetry.db")


def get_db_connection():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS request_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            http_method TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            response_time_ms REAL NOT NULL,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telemetry_id INTEGER NOT NULL,
            payload_sample TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            flagged_categories TEXT NOT NULL,
            remediation_action TEXT NOT NULL,
            inspection_time_ms REAL NOT NULL,
            raw_llm_output TEXT,
            analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (telemetry_id) REFERENCES request_telemetry (id) ON DELETE CASCADE
        );
    """
    )

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON"
        " request_telemetry(timestamp);"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_telemetry_client_ip ON"
        " request_telemetry(client_ip);"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_audits_telemetry_id ON"
        " security_audits(telemetry_id);"
    )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()