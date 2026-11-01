import json
import sqlite3

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


DATABASE = str(
    Path(__file__).resolve().parent / "drift_detection.db"
)

# Existing storage code continues using this default.
RESOURCE_NAME = "clouddriftlab2026"


def timestamp():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def database_connection():
    connection = sqlite3.connect(DATABASE)

    try:
        with connection:
            yield connection
    finally:
        connection.close()


def stored_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)

    return str(value)


# ============================================================
# Database tables
# ============================================================

def create_database():
    with database_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                resource_name TEXT NOT NULL,
                setting TEXT NOT NULL,
                expected_value TEXT,
                actual_value TEXT,
                severity TEXT,
                title TEXT,
                reason TEXT,
                recommendation TEXT,
                status TEXT
            )
        """)


def create_scan_table():
    with database_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_name TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                result TEXT,
                drift_count INTEGER,
                finding_count INTEGER,
                error_message TEXT
            )
        """)


# ============================================================
# Finding operations
# ============================================================

def _save_finding(connection, finding, resource_name):
    declared_resource = finding.get("resource_name")

    if (
        declared_resource is not None
        and declared_resource != resource_name
    ):
        raise ValueError(
            "The finding belongs to a different resource."
        )

    existing = connection.execute("""
        SELECT id
        FROM findings
        WHERE resource_name = ?
          AND setting = ?
          AND status = 'OPEN'
    """, (
        resource_name,
        finding["setting"]
    )).fetchone()

    values = (
        stored_value(finding["expected"]),
        stored_value(finding["actual"]),
        finding["severity"],
        finding["title"],
        finding["reason"],
        finding["recommendation"]
    )

    if existing:
        # Refresh the current evidence without creating a duplicate.
        # Keep the original detection timestamp.
        connection.execute("""
            UPDATE findings
            SET expected_value = ?,
                actual_value = ?,
                severity = ?,
                title = ?,
                reason = ?,
                recommendation = ?
            WHERE id = ?
        """, values + (existing[0],))

    else:
        connection.execute("""
            INSERT INTO findings (
                timestamp,
                resource_name,
                setting,
                expected_value,
                actual_value,
                severity,
                title,
                reason,
                recommendation,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp(),
            resource_name,
            finding["setting"],
            *values,
            "OPEN"
        ))


def _resolve_findings(
    connection,
    current_findings,
    resource_name
):
    active_settings = {
        finding["setting"]
        for finding in current_findings
    }

    open_findings = connection.execute("""
        SELECT id, setting
        FROM findings
        WHERE resource_name = ?
          AND status = 'OPEN'
    """, (
        resource_name,
    )).fetchall()

    for finding_id, setting in open_findings:
        if setting not in active_settings:
            connection.execute("""
                UPDATE findings
                SET status = 'RESOLVED'
                WHERE id = ?
            """, (
                finding_id,
            ))


def save_finding(finding, resource_name=RESOURCE_NAME):
    with database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")

        _save_finding(
            connection,
            finding,
            resource_name
        )


def resolve_findings(
    current_findings,
    resource_name=RESOURCE_NAME
):
    with database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")

        _resolve_findings(
            connection,
            current_findings,
            resource_name
        )


# ============================================================
# Scan operations
# ============================================================

def start_scan(resource_name):
    with database_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO scans (
                resource_name,
                started_at,
                status
            )
            VALUES (?, ?, 'RUNNING')
        """, (
            resource_name,
            timestamp()
        ))

        return cursor.lastrowid


def _finish_scan(
    connection,
    scan_id,
    status,
    result=None,
    drift_count=None,
    finding_count=None,
    error_message=None
):
    if status not in {"SUCCESS", "FAILED"}:
        raise ValueError(
            "Scan status must be SUCCESS or FAILED."
        )

    cursor = connection.execute("""
        UPDATE scans
        SET finished_at = ?,
            status = ?,
            result = ?,
            drift_count = ?,
            finding_count = ?,
            error_message = ?
        WHERE id = ?
          AND status = 'RUNNING'
    """, (
        timestamp(),
        status,
        result,
        drift_count,
        finding_count,
        error_message,
        scan_id
    ))

    if cursor.rowcount != 1:
        raise ValueError(
            "The scan does not exist or is already finished."
        )


def finish_scan(
    scan_id,
    status,
    result=None,
    drift_count=None,
    finding_count=None,
    error_message=None
):
    with database_connection() as connection:
        _finish_scan(
            connection,
            scan_id,
            status,
            result,
            drift_count,
            finding_count,
            error_message
        )


# ============================================================
# Save a complete assessment in one transaction
# ============================================================

def complete_scan(
    scan_id,
    resource_name,
    findings,
    drift_count,
    result
):
    with database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")

        scan = connection.execute("""
            SELECT resource_name, status
            FROM scans
            WHERE id = ?
        """, (
            scan_id,
        )).fetchone()

        if scan != (resource_name, "RUNNING"):
            raise ValueError(
                "Scan resource or status does not match."
            )

        for finding in findings:
            _save_finding(
                connection,
                finding,
                resource_name
            )

        _resolve_findings(
            connection,
            findings,
            resource_name
        )

        _finish_scan(
            connection=connection,
            scan_id=scan_id,
            status="SUCCESS",
            result=result,
            drift_count=drift_count,
            finding_count=len(findings)
        )