# 🗄️ secure-data-pipeline

[![Language: Python](https://img.shields.io/badge/Language-Python-3776AB?style=flat&logo=python&logoColor=white)](#)
[![Database: SQLite / PostgreSQL](https://img.shields.io/badge/Database-Relational%20SQL-4479A1?style=flat&logo=sqlite&logoColor=white)](#)
[![Integrity: SHA-256](https://img.shields.io/badge/Integrity-SHA--256%20Verified-blue.svg)](#)

> Automated ETL pipeline providing input sanitization, cryptographic file checksumming, relational constraint validation, and immutable audit logging for enterprise data stores.

---

### 📌 Architectural Highlights
* **Cryptographic Ingestion Verification:** Computes and logs SHA-256 checksums of source files to verify data integrity prior to ingestion.
* **Sanitization & Input Validation:** Strips script tags, invalid escape characters, and SQL-injection indicators before executing database parameterized queries.
* **Immutable Audit Trail:** Maintains a UTC-timestamped event log (`pipeline_audit.log`) tracking ingestion lifecycle, integrity rejections, and schema constraints.
* **Relational Schema Governance:** Enforces unique primary constraints, type checks, and structured storage.

---

### ⚙ Execution & Quickstart

```bash
# Clone the repository
git clone [https://github.com/Gibson13/secure-data-pipeline.git](https://github.com/Gibson13/secure-data-pipeline.git)
cd secure-data-pipeline

# Execute the pipeline (generates demo data, initializes schema, runs ingestion)
python pipeline.py
