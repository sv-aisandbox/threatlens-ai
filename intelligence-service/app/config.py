"""Connection settings. Values come from the environment / repo-root .env, never from code."""

import os
from pathlib import Path

from dotenv import load_dotenv
from neo4j import Driver, GraphDatabase

REPO_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(REPO_ROOT / ".env")


def get_driver() -> Driver:
    host = os.environ.get("MEMGRAPH_HOST", "localhost")
    port = os.environ.get("MEMGRAPH_PORT", "7687")
    user = os.environ.get("MEMGRAPH_USER") or None
    password = os.environ.get("MEMGRAPH_PASSWORD") or ""
    auth = (user, password) if user else None
    return GraphDatabase.driver(f"bolt://{host}:{port}", auth=auth)
