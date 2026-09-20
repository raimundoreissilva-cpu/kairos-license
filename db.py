"""Conexão com o Neon (mesma DATABASE_URL do app desktop) para o servidor
de licenciamento. Separado do db.py do app cliente — este roda só no
servidor, nunca vai pro build do .exe."""
from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path

import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL não definida. Configure no .env (veja .env.example) "
        "com a connection string do Neon."
    )


@contextmanager
def get_conn():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def get_cursor():
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            yield cur


def init_schema() -> None:
    """Roda o schema_licenses.sql — idempotente (CREATE TABLE IF NOT EXISTS),
    seguro pra chamar toda vez que o servidor sobe."""
    schema_path = Path(__file__).resolve().parent / "schema_licenses.sql"
    sql = schema_path.read_text(encoding="utf-8")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
