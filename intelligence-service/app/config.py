"""Connection settings. Values come from the environment / repo-root .env, never from code."""

import os
from pathlib import Path

from dotenv import load_dotenv
from neo4j import Driver, GraphDatabase

REPO_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(REPO_ROOT / ".env")


def get_driver() -> Driver:
    host = os.environ.get("MEMGRAPH_HOST", "127.0.0.1")
    port = os.environ.get("MEMGRAPH_PORT", "7687")
    user = os.environ.get("MEMGRAPH_USER") or None
    password = os.environ.get("MEMGRAPH_PASSWORD") or ""
    auth = (user, password) if user else None
    return GraphDatabase.driver(f"bolt://{host}:{port}", auth=auth)


def get_test_driver() -> Driver:
    """Driver for the disposable test Memgraph (never the development one)."""
    port = os.environ.get("MEMGRAPH_TEST_PORT", "7688")
    if port == os.environ.get("MEMGRAPH_PORT", "7687"):
        raise RuntimeError("MEMGRAPH_TEST_PORT must differ from MEMGRAPH_PORT")
    host = os.environ.get("MEMGRAPH_HOST", "127.0.0.1")
    return GraphDatabase.driver(f"bolt://{host}:{port}", auth=None)


def pg_conninfo() -> str:
    return (
        f"host={os.environ.get('POSTGRES_HOST', '127.0.0.1')} "
        f"port={os.environ.get('POSTGRES_PORT', '5432')} "
        f"dbname={os.environ.get('POSTGRES_DB', 'threatlens')} "
        f"user={os.environ.get('POSTGRES_USER', 'threatlens')} "
        f"password={os.environ.get('POSTGRES_PASSWORD', '')}"
    )


def nvd_api_key() -> str | None:
    key = os.environ.get("NVD_API_KEY", "").strip()
    return None if not key or key == "your-nvd-api-key" else key
