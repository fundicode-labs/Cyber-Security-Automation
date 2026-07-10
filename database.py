"""Database connection helpers for SQLite and PostgreSQL."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from collections.abc import Mapping
class HybridRow(Mapping):
    def __init__(self, columns, values):
        self._columns = list(columns)
        self._values = tuple(values)
        self._data = {column: value for column, value in zip(self._columns, self._values)}

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._values)

    def keys(self):
        return self._data.keys()

    def items(self):
        return self._data.items()

    def values(self):
        return self._data.values()

    def __repr__(self):
        return repr(self._data)



BASE_DIR = os.path.dirname(__file__)
SQLITE_DB_PATH = os.path.join(BASE_DIR, "database.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()


def is_postgres_enabled() -> bool:
    return DATABASE_URL.startswith("postgresql://") or DATABASE_URL.startswith("postgres://")


def _convert_placeholders(query: str) -> str:
    if is_postgres_enabled():
        return query.replace("?", "%s")
    return query


@dataclass
class DatabaseCursor:
    _cursor: object

    def execute(self, query, params=None):
        converted_query = _convert_placeholders(query)
        if params is None:
            return self._cursor.execute(converted_query)
        return self._cursor.execute(converted_query, params)

    def executemany(self, query, params_seq):
        converted_query = _convert_placeholders(query)
        return self._cursor.executemany(converted_query, params_seq)

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        columns = [description[0] for description in self._cursor.description or []]
        return HybridRow(columns, row)

    def fetchall(self):
        rows = self._cursor.fetchall()
        columns = [description[0] for description in self._cursor.description or []]
        return [HybridRow(columns, row) for row in rows]

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class DatabaseConnection:
    def __init__(self):
        if is_postgres_enabled():
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as exc:
                raise RuntimeError(
                    "DATABASE_URL is configured for PostgreSQL, but psycopg is not installed."
                ) from exc

            self._conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
            self._postgres = True
        else:
            self._conn = sqlite3.connect(SQLITE_DB_PATH)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._postgres = False

    def cursor(self):
        return DatabaseCursor(self._conn.cursor())

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        self.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __setattr__(self, name, value):
        if name in {"_conn", "_postgres"}:
            super().__setattr__(name, value)
            return
        if name == "row_factory" and getattr(self, "_postgres", False):
            return
        setattr(self._conn, name, value)


def connect():
    return DatabaseConnection()
