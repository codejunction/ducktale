"""Ducktale MVP: one DuckDB SQL workspace over many datasources. Run: uvicorn app:app"""
import json
import os
import sqlite3
import threading
from contextlib import closing
from pathlib import Path

import duckdb
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

META_PATH = os.environ.get("DUCKTALE_DB", "ducktale.db")
MEMORY_LIMIT = os.environ.get("DUCKTALE_MEMORY", "2GB")
TIMEOUT_S = float(os.environ.get("DUCKTALE_TIMEOUT", 300))


def meta(sql, args=()):
    with closing(sqlite3.connect(META_PATH)) as m, m:
        return m.execute(sql, args).fetchall()


meta("CREATE TABLE IF NOT EXISTS datasources(name TEXT PRIMARY KEY, type TEXT, config TEXT)")
meta("CREATE TABLE IF NOT EXISTS history(id TEXT, sql TEXT, status TEXT, rows INT, error TEXT,"
     " at TEXT DEFAULT CURRENT_TIMESTAMP)")


def lit(v):
    return "'" + str(v).replace("'", "''") + "'"


def ident(v):
    return '"' + str(v).replace('"', '""') + '"'


def secret(name, params):
    if not all(k.isidentifier() for k in params):
        raise ValueError("secret keys must be identifiers")
    value = lambda v: str(v).lower() if isinstance(v, bool) else lit(v)
    return f"CREATE SECRET {ident(name)} ({', '.join(f'{k} {value(v)}' for k, v in params.items())})"


# Connector: (name, config) -> (DuckDB statements, directories the sandbox may still read).
# New source type = one function here; the query path never looks at types.
def postgres(n, c):
    return ["INSTALL postgres", "LOAD postgres",
            secret(n, {"TYPE": "postgres", "HOST": c["host"], "PORT": c.get("port", 5432),
                       "DATABASE": c["database"], "USER": c["user"], "PASSWORD": c["password"]}),
            f"ATTACH '' AS {ident(n)} (TYPE postgres, SECRET {ident(n)}, READ_ONLY)"], []


def sqlserver(n, c):
    dsn = (f"Server={c['host']},{c.get('port', 1433)};Database={c['database']};"
           f"User Id={c['user']};Password={c['password']};Encrypt={c.get('encrypt', 'yes')}")
    return ["INSTALL mssql FROM community", "LOAD mssql",
            f"ATTACH {lit(dsn)} AS {ident(n)} (TYPE mssql, READ_ONLY)"], []


def mongo(n, c):
    return ["INSTALL mongo FROM community", "LOAD mongo",
            f"ATTACH {lit(c['uri'])} AS {ident(n)} (TYPE mongo, READ_ONLY)"], []


def iceberg(n, c):  # IOMETE and any Iceberg REST catalog
    return ["INSTALL httpfs", "LOAD httpfs", "INSTALL iceberg", "LOAD iceberg",
            secret(n, {"TYPE": "iceberg", **c.get("secret", {})}),
            f"ATTACH {lit(c['warehouse'])} AS {ident(n)} (TYPE iceberg, ENDPOINT {lit(c['endpoint'])}, SECRET {ident(n)})"], []


def files(n, c):  # S3(-compatible) or local Parquet/CSV/JSON: {"tables": {"orders": "s3://b/orders/*.parquet"}, "secret": {...}}
    s = dict(c.get("secret") or {})
    if "://" in s.get("ENDPOINT", ""):  # MinIO/R2/Ceph style "http://host:9000" -> host + SSL flag + path-style URLs
        scheme, s["ENDPOINT"] = s["ENDPOINT"].rstrip("/").split("://", 1)
        s.setdefault("USE_SSL", scheme == "https")
        s.setdefault("URL_STYLE", "path")
    bucket = c.get("bucket", "").strip("/")
    tables = {t: f"s3://{bucket}/{p.lstrip('/')}" if bucket and "://" not in p else p for t, p in c["tables"].items()}
    stmts = ["INSTALL httpfs", "LOAD httpfs"] + ([secret(n, s)] if s else [])
    stmts.append(f"CREATE SCHEMA {ident(n)}")
    stmts += [f"CREATE VIEW {ident(n)}.{ident(t)} AS FROM {lit(p)}" for t, p in tables.items()]
    return stmts, [p[:p.replace("\\", "/").rfind("/") + 1] for p in tables.values()]


CONNECTORS = {"postgres": postgres, "sqlserver": sqlserver, "mongo": mongo, "iceberg": iceberg, "s3": files, "files": files}

# ponytail: one shared DuckDB per process, rebuilt on datasource change; per-user sessions/workers when multi-tenant.
ENGINE = {"db": None}
BUILD_LOCK = threading.Lock()
RUNNING = {}
FILE_WRITES = {duckdb.StatementType.COPY, duckdb.StatementType.COPY_DATABASE, duckdb.StatementType.EXPORT}


def build(sources):
    db = duckdb.connect(config={"memory_limit": MEMORY_LIMIT})
    allowed = []
    for name, typ, config in sources:
        try:
            stmts, dirs = CONNECTORS[typ](name, config)
            for s in stmts:
                db.execute(s)
        except (duckdb.Error, KeyError, ValueError) as e:
            db.close()
            raise HTTPException(400, f"datasource {name}: {type(e).__name__}: {e}")
        allowed += dirs
    # Sandbox: no new files, URLs, ATTACH, INSTALL or SET from user SQL. Secrets stay redacted.
    db.execute(f"SET allowed_directories=[{', '.join(map(lit, allowed))}]")
    db.execute("SET enable_external_access=false")
    db.execute("SET lock_configuration=true")
    return db


def stored():
    return [(n, t, json.loads(c)) for n, t, c in meta("SELECT name, type, config FROM datasources")]


def swap(sources):
    with BUILD_LOCK:
        ENGINE["db"] = build(sources)


app = FastAPI(title="Ducktale")
swap(stored())


class Datasource(BaseModel):
    name: str
    type: str
    config: dict


class Query(BaseModel):
    id: str
    sql: str
    limit: int = 1000


@app.get("/")
def index():
    return FileResponse(Path(__file__).with_name("index.html"))


@app.get("/api/datasources")
def list_datasources():
    return [{"name": n, "type": t} for n, t, _ in stored()]


@app.post("/api/datasources")
def add_datasource(d: Datasource):
    if not d.name.isidentifier() or d.type not in CONNECTORS:
        raise HTTPException(400, f"name must be an identifier; type one of {list(CONNECTORS)}")
    swap([s for s in stored() if s[0] != d.name] + [(d.name, d.type, d.config)])  # raises = connection test failed
    meta("INSERT OR REPLACE INTO datasources VALUES (?, ?, ?)", (d.name, d.type, json.dumps(d.config)))
    return {"ok": True}


@app.delete("/api/datasources/{name}")
def delete_datasource(name: str):
    meta("DELETE FROM datasources WHERE name = ?", (name,))
    swap(stored())
    return {"ok": True}


@app.get("/api/catalog")
def catalog():
    rows = ENGINE["db"].cursor().execute(
        "SELECT database_name, schema_name, table_name, column_name, data_type FROM duckdb_columns()"
        " WHERE NOT internal AND database_name NOT IN ('system', 'temp') ORDER BY ALL").fetchall()
    return [dict(zip(("database", "schema", "table", "column", "type"), r)) for r in rows]


@app.post("/api/query")
def run_query(q: Query):
    cur = ENGINE["db"].cursor()
    RUNNING[q.id] = cur
    timer = threading.Timer(TIMEOUT_S, cur.interrupt)
    timer.start()
    try:
        # allowed_directories also permits writes, so file-writing statements are refused outright.
        if {s.type for s in cur.extract_statements(q.sql)} & FILE_WRITES:
            raise duckdb.PermissionException("COPY / EXPORT are not allowed")
        cur.execute(q.sql)
        cols = [d[0] for d in cur.description or []]
        rows = cur.fetchmany(q.limit) if cols else []
    except duckdb.Error as e:
        meta("INSERT INTO history(id, sql, status, error) VALUES (?, ?, 'FAILED', ?)", (q.id, q.sql, str(e)))
        raise HTTPException(400, f"{type(e).__name__}: {e}")
    finally:
        timer.cancel()
        RUNNING.pop(q.id, None)
        cur.close()
    meta("INSERT INTO history(id, sql, status, rows) VALUES (?, ?, 'SUCCESS', ?)", (q.id, q.sql, len(rows)))
    return {"columns": cols, "rows": rows, "truncated": len(rows) == q.limit}


@app.post("/api/query/{qid}/cancel")
def cancel_query(qid: str):
    cur = RUNNING.get(qid)
    if cur:
        cur.interrupt()
    return {"cancelled": bool(cur)}


@app.get("/api/history")
def history(offset: int = 0, limit: int = 20):
    rows = meta("SELECT id, sql, status, rows, error, at FROM history ORDER BY at DESC, rowid DESC LIMIT ? OFFSET ?",
                (min(limit, 100), max(offset, 0)))
    return {"total": meta("SELECT count(*) FROM history")[0][0],
            "items": [dict(zip(("id", "sql", "status", "rows", "error", "at"), r)) for r in rows]}
