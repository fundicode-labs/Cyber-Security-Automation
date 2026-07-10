"""Backup and restore helpers for the Cyber Security Automation app."""

import os
import shutil
from datetime import datetime

from database import DATABASE_URL, is_postgres_enabled


BASE_DIR = os.path.dirname(__file__)
DATABASE_PATH = os.path.join(BASE_DIR, "database.db")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")


def ensure_backup_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    return BACKUP_DIR


def create_backup():
    ensure_backup_dir()
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if is_postgres_enabled():
        backup_name = f"database_{timestamp}.sql"
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        pg_dump = shutil.which("pg_dump")
        if not pg_dump:
            raise RuntimeError("pg_dump is required for PostgreSQL backups.")

        import subprocess

        result = subprocess.run(
            [pg_dump, DATABASE_URL, "-f", backup_path],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Failed to create PostgreSQL backup.")
        return backup_path

    backup_name = f"database_{timestamp}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    shutil.copy2(DATABASE_PATH, backup_path)
    return backup_path


def list_backups():
    ensure_backup_dir()
    backups = []
    for entry in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if entry.endswith(".db") or entry.endswith(".sql"):
            backup_path = os.path.join(BACKUP_DIR, entry)
            backups.append({
                "name": entry,
                "path": backup_path,
                "size": os.path.getsize(backup_path),
                "modified": datetime.fromtimestamp(os.path.getmtime(backup_path)).isoformat(timespec="seconds"),
            })
    return backups


def restore_backup(backup_path):
    if not os.path.isfile(backup_path):
        raise FileNotFoundError(backup_path)
    if is_postgres_enabled():
        psql = shutil.which("psql")
        if not psql:
            raise RuntimeError("psql is required to restore PostgreSQL backups.")

        import subprocess

        result = subprocess.run(
            [psql, DATABASE_URL, "-f", backup_path],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Failed to restore PostgreSQL backup.")
        return DATABASE_PATH

    shutil.copy2(backup_path, DATABASE_PATH)
    return DATABASE_PATH