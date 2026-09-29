#!/usr/bin/env python3
"""
secure-data-pipeline
Author: Joris Gibson
Description: Automated data ingestion, validation, and sanitization pipeline.
Demonstrates structured ETL, SQL schema compliance, and audit logging.
"""

import sqlite3
import csv
import re
import os
import hashlib
from datetime import datetime, timezone

DB_NAME = "pipeline_records.db"
AUDIT_LOG = "pipeline_audit.log"

def log_event(event_type, details):
    """Writes an immutable timestamped entry to the audit log."""
    utc_now = datetime.now(timezone.utc).isoformat()
    entry = f"[{utc_now}] [{event_type}] {details}\n"
    with open(AUDIT_LOG, "a") as f:
        f.write(entry)

def calculate_checksum(filepath):
    """Computes SHA-256 hash of the ingested file to verify data integrity."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def sanitize_text(text):
    """Strips leading/trailing whitespace and removes potentially malicious SQL/control chars."""
    if not text:
        return ""
    # Strip script/injection indicators and normalize whitespace
    cleaned = re.sub(r"[<>{};]", "", text)
    return cleaned.strip()

def initialize_database():
    """Initializes the SQLite relational database schema with constraints."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS personnel_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            department TEXT NOT NULL,
            clearance_level TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    log_event("SYS_INIT", "Database schema initialized successfully.")

def ingest_csv(filepath):
    """Parses, validates, and commits records from an input CSV."""
    if not os.path.exists(filepath):
        print(f"[-] Error: File {filepath} not found.")
        return

    checksum = calculate_checksum(filepath)
    log_event("INGEST_START", f"Processing {filepath} (SHA-256: {checksum})")

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    valid_count = 0
    rejected_count = 0

    with open(filepath, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            record_id = sanitize_text(row.get("record_id", ""))
            name = sanitize_text(row.get("full_name", ""))
            dept = sanitize_text(row.get("department", ""))
            clearance = sanitize_text(row.get("clearance_level", "PUBLIC"))

            # Validation logic
            if not record_id or not name:
                rejected_count += 1
                log_event("VALIDATION_FAIL", f"Record rejected due to missing primary fields: {row}")
                continue

            try:
                cursor.execute("""
                    INSERT INTO personnel_records (record_id, full_name, department, clearance_level, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (record_id, name, dept, clearance, datetime.now(timezone.utc).isoformat()))
                valid_count += 1
            except sqlite3.IntegrityError:
                rejected_count += 1
                log_event("INTEGRITY_FAIL", f"Duplicate record_id flagged: {record_id}")

    conn.commit()
    conn.close()

    log_event("INGEST_COMPLETE", f"Ingested {valid_count} valid records. Rejected {rejected_count} records.")
    print(f"[+] Ingestion complete. Committed: {valid_count}, Rejected: {rejected_count}")

def generate_sample_dataset(filepath="sample_input.csv"):
    """Creates a sample dataset for demonstration purposes."""
    data = [
        ["record_id", "full_name", "department", "clearance_level"],
        ["REC-101", "Alex Vance", "Cyber Defense", "Secret"],
        ["REC-102", "Gordon Freeman", "Applied Physics", "Top Secret"],
        ["REC-103", "Eli Vance; DROP TABLE", "Operations", "Public"],
        ["REC-101", "Alex Vance Duplicate", "Cyber Defense", "Secret"]  # Deliberate duplicate
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(data)
    print(f"[*] Generated sample dataset: {filepath}")

if __name__ == "__main__":
    initialize_database()
    sample_file = "sample_input.csv"
    generate_sample_dataset(sample_file)
    ingest_csv(sample_file)
