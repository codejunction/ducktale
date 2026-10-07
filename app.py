"""Ducktale: one DuckDB SQL workspace over many datasources. Run: uvicorn app:app"""
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import threading
from contextlib import closing
from pathlib import Path

import duckdb
from cryptography.fernet import Fernet
from fastapi import Cookie, Depends, FastAPI, HTTPException, Response
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

META_PATH = os.environ.get("DUCKTALE_DB", "ducktale.db")
MEMORY_LIMIT = os.environ.get("DUCKTALE_MEMORY", "2GB")
TIMEOUT_S = float(os.environ.get("DUCKTALE_TIMEOUT", 300))
SESSION_DAYS = 7


def meta(sql, args=()):
    with closing(sqlite3.connect(META_PATH)) as m, m:
        return m.execute(sql, args).fetchall()


meta("CREATE TABLE IF NOT EXISTS datasources(name TEXT PRIMARY KEY, type TEXT, config TEXT)")
meta("CREATE TABLE IF NOT EXISTS history(id TEXT, sql TEXT, status TEXT, rows INT, error TEXT,"
     " at TEXT DEFAULT CURRENT_TIMESTAMP)")
meta("CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY, pw TEXT, admin INT, datasources TEXT)")
meta("CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, email TEXT, expires TEXT)")
meta("CREATE TABLE IF NOT EXISTS saved_queries(id INTEGER PRIMARY KEY, owner TEXT, name TEXT, sql TEXT,"
     " updated_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(owner, name))")
if "email" not in [c[1] for c in meta("PRAGMA table_info(history)")]:
    meta("ALTER TABLE history ADD COLUMN email TEXT")


# --- Credentials at rest: datasource configs are Fernet-encrypted with a key outside the metadata DB.
def load_key():
    if key := os.environ.get("DUCKTALE_SECRET_KEY"):
        return key.encode()
    path = Path(META_PATH + ".key")
    if not path.exists():
        path.write_bytes(Fernet.generate_key())
        path.chmod(0o600)
    return path.read_bytes()


FERNET = Fernet(load_key())


def seal(config):
    return FERNET.encrypt(json.dumps(config).encode()).decode()


def unseal(blob):
    return json.loads(FERNET.decrypt(blob) if blob.startswith("gAAAA") else blob)


for _n, _c in meta("SELECT name, config FROM datasources WHERE config NOT LIKE 'gAAAA%'"):  # migrate plaintext rows
    meta("UPDATE datasources SET config = ? WHERE name = ?", (seal(json.loads(_c)), _n))


# --- Connectors
def lit(v):
    return "'" + str(v).replace("'", "''") + "'"


def ident(v):
    return '"' + str(v).replace('"', '""') + '"'


def secret(name, params):
    if not all(k.isidentifier() for k in params):
        raise ValueError("secret keys must be identifiers")
    value = lambda v: str(v).lower() if isinstance(v, bool) else lit(v)
    return f"CREATE SECRET {ident(name)} ({', '.join(f'{k} {value(v)}' for k, v in params.items())})"


# Connector: (duckdb, name, config) -> directories the sandbox may still read. It attaches its source(s).
# New source type = one function here; the query path never looks at types.
def statements(fn):
    """Adapt a connector that is a fixed list of SQL to the (db, name, config) -> dirs protocol."""
    def connect(db, n, c):
        stmts, dirs = fn(n, c)
        for s in stmts:
            db.execute(s)
        return dirs
    return connect


def postgres(db, n, c):
    """database: one name -> catalog <n>; "a, b" or "*" (every database on the server) -> catalogs <n>_<db>."""
    wanted = [d.strip() for d in str(c.get("database") or "*").split(",") if d.strip()]
    db.execute("INSTALL postgres")
    db.execute("LOAD postgres")
    db.execute(secret(n, {"TYPE": "postgres", "HOST": c["host"], "PORT": c.get("port", 5432),
                          "DATABASE": "postgres" if "*" in wanted else wanted[0], "USER": c["user"], "PASSWORD": c["password"]}))
    if "*" in wanted:
        probe = ident(n + "__probe")
        db.execute(f"ATTACH '' AS {probe} (TYPE postgres, SECRET {ident(n)}, READ_ONLY)")
        wanted = [r[0] for r in db.execute(f"SELECT datname FROM postgres_query({lit(n + '__probe')},"
                                           " 'SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY 1')").fetchall()]
        db.execute(f"DETACH {probe}")
    for d in wanted:
        alias = n if len(wanted) == 1 else f"{n}_{''.join(ch if ch.isalnum() else '_' for ch in d)}"
        db.execute(f"ATTACH {lit('dbname=' + d)} AS {ident(alias)} (TYPE postgres, SECRET {ident(n)}, READ_ONLY)")
    return []


@statements
def sqlserver(n, c):
    dsn = (f"Server={c['host']},{c.get('port', 1433)};Database={c['database']};"
           f"User Id={c['user']};Password={c['password']};Encrypt={c.get('encrypt', 'yes')}")
    return ["INSTALL mssql FROM community", "LOAD mssql",
            f"ATTACH {lit(dsn)} AS {ident(n)} (TYPE mssql, READ_ONLY)"], []


@statements
def mongo(n, c):
    return ["INSTALL mongo FROM community", "LOAD mongo",
            f"ATTACH {lit(c['uri'])} AS {ident(n)} (TYPE mongo, READ_ONLY)"], []


@statements
def iceberg(n, c):  # IOMETE and any Iceberg REST catalog; namespaces -> schemas, tables discovered on attach
    # The REST spec has no "list warehouses" call, so several catalogs are listed explicitly: "a, b" -> <n>_a, <n>_b.
    whs = [w.strip() for w in c["warehouse"].split(",") if w.strip()]
    alias = lambda w: n if len(whs) == 1 else f"{n}_{''.join(ch if ch.isalnum() else '_' for ch in w)}"
    return ["INSTALL httpfs", "LOAD httpfs", "INSTALL iceberg", "LOAD iceberg",
            secret(n, {"TYPE": "iceberg", **c.get("secret", {})})] + [
            f"ATTACH {lit(w)} AS {ident(alias(w))} (TYPE iceberg, ENDPOINT {lit(c['endpoint'])}, SECRET {ident(n)})" for w in whs], []


@statements
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

# --- Engines: one sandboxed DuckDB per distinct set of datasources a user may see. Datasources a user is not
# granted are never attached to their engine, so access control is enforced by DuckDB itself, not by parsing SQL.
# ponytail: one engine per access set; temp tables are shared by users with the same set. Per-user sessions when needed.
ENGINES, CATALOG, HEALTH = {}, {}, {}
BUILD_LOCK = threading.Lock()
RUNNING = {}
FILE_WRITES = {duckdb.StatementType.COPY, duckdb.StatementType.COPY_DATABASE, duckdb.StatementType.EXPORT}


def build(sources, strict=False):
    db = duckdb.connect(config={"memory_limit": MEMORY_LIMIT})
    allowed = []
    for name, typ, config in sources:
        try:
            allowed += CONNECTORS[typ](db, name, config)
            HEALTH[name] = None
        except (duckdb.Error, KeyError, ValueError) as e:
            msg = f"{type(e).__name__}: {e}"
            if strict:
                db.close()
                raise HTTPException(400, f"datasource {name}: {msg}")
            HEALTH[name] = msg  # a broken source must not take the others down
    # Sandbox: no new files, URLs, ATTACH, INSTALL or SET from user SQL. Secrets stay redacted.
    db.execute(f"SET allowed_directories=[{', '.join(map(lit, allowed))}]")
    db.execute("SET enable_external_access=false")
    db.execute("SET lock_configuration=true")
    return db


def stored():
    return [(n, t, unseal(c)) for n, t, c in meta("SELECT name, type, config FROM datasources")]


def allowed_names(user):
    names = [r[0] for r in meta("SELECT name FROM datasources ORDER BY name")]
    return names if user["admin"] or user["datasources"] is None else [n for n in names if n in user["datasources"]]


def engine(user):
    key = frozenset(allowed_names(user))
    with BUILD_LOCK:
        if key not in ENGINES:
            ENGINES[key] = build([s for s in stored() if s[0] in key])
        return key, ENGINES[key]


def invalidate():
    with BUILD_LOCK:
        ENGINES.clear()
        CATALOG.clear()


# --- Auth: email/password, PBKDF2 hashes, opaque session cookie (stored hashed).
def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 600_000).hex()


def check_pw(pw, stored_hash):
    return hmac.compare_digest(hash_pw(pw, stored_hash.split("$")[0]), stored_hash)


def sha(token):
    return hashlib.sha256(token.encode()).hexdigest()


def current_user(ducktale_session: str | None = Cookie(None)):
    rows = ducktale_session and meta(
        "SELECT u.email, u.admin, u.datasources FROM sessions s JOIN users u USING (email)"
        " WHERE s.token = ? AND s.expires > datetime('now')", (sha(ducktale_session),))
    if not rows:
        raise HTTPException(401, "login required")
    email, admin, ds = rows[0]
    return {"email": email, "admin": bool(admin), "datasources": None if ds is None else json.loads(ds)}


def admin_user(user=Depends(current_user)):
    if not user["admin"]:
        raise HTTPException(403, "admin only")
    return user


app = FastAPI(title="Ducktale")


class Credentials(BaseModel):
    email: str
    password: str


class NewUser(Credentials):
    admin: bool = False
    datasources: list[str] | None = None  # None = all datasources


class Datasource(BaseModel):
    name: str
    type: str
    config: dict


class Query(BaseModel):
    id: str
    sql: str
    limit: int = 1000


class SavedQuery(BaseModel):
    name: str
    sql: str


@app.get("/")
def index():
    return FileResponse(Path(__file__).with_name("index.html"))


@app.get("/api/setup")
def setup_needed():
    return {"needed": not meta("SELECT 1 FROM users LIMIT 1")}


@app.post("/api/login")
def login(c: Credentials, response: Response):
    email = c.email.strip().lower()
    if not meta("SELECT 1 FROM users LIMIT 1"):  # first login on a fresh install creates the admin
        create_user(NewUser(email=email, password=c.password, admin=True), None)
    row = meta("SELECT pw FROM users WHERE email = ?", (email,))
    if not row or not check_pw(c.password, row[0][0]):
        raise HTTPException(401, "invalid email or password")
    token = secrets.token_urlsafe(32)
    meta("DELETE FROM sessions WHERE expires < datetime('now')")
    meta(f"INSERT INTO sessions VALUES (?, ?, datetime('now', '+{SESSION_DAYS} days'))", (sha(token), email))
    response.set_cookie("ducktale_session", token, httponly=True, samesite="strict", max_age=SESSION_DAYS * 86400)
    return {"ok": True}


@app.post("/api/logout")
def logout(response: Response, ducktale_session: str | None = Cookie(None)):
    if ducktale_session:
        meta("DELETE FROM sessions WHERE token = ?", (sha(ducktale_session),))
    response.delete_cookie("ducktale_session")
    return {"ok": True}


@app.get("/api/me")
def me(user=Depends(current_user)):
    return user


@app.get("/api/users")
def list_users(_=Depends(admin_user)):
    return [{"email": e, "admin": bool(a), "datasources": None if d is None else json.loads(d)}
            for e, a, d in meta("SELECT email, admin, datasources FROM users ORDER BY email")]


@app.post("/api/users")
def create_user(u: NewUser, _=Depends(admin_user)):
    if "@" not in u.email or len(u.password) < 8:
        raise HTTPException(400, "valid email and a password of at least 8 characters required")
    ds = None if u.admin or u.datasources is None else json.dumps(u.datasources)
    meta("INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?)", (u.email.strip().lower(), hash_pw(u.password), int(u.admin), ds))
    return {"ok": True}


@app.delete("/api/users/{email}")
def delete_user(email: str, user=Depends(admin_user)):
    if email == user["email"]:
        raise HTTPException(400, "cannot delete yourself")
    meta("DELETE FROM users WHERE email = ?", (email,))
    meta("DELETE FROM sessions WHERE email = ?", (email,))
    return {"ok": True}


@app.get("/api/datasources")
def list_datasources(user=Depends(current_user)):
    names = set(allowed_names(user))
    return [{"name": n, "type": t, "error": HEALTH.get(n)}
            for n, t in meta("SELECT name, type FROM datasources ORDER BY name") if n in names]


@app.post("/api/datasources")
def add_datasource(d: Datasource, _=Depends(admin_user)):
    if not d.name.isidentifier() or d.type not in CONNECTORS:
        raise HTTPException(400, f"name must be an identifier; type one of {list(CONNECTORS)}")
    build([(d.name, d.type, d.config)], strict=True).close()  # connection test; raises on failure
    meta("INSERT OR REPLACE INTO datasources VALUES (?, ?, ?)", (d.name, d.type, seal(d.config)))
    invalidate()
    return {"ok": True}


@app.delete("/api/datasources/{name}")
def delete_datasource(name: str, _=Depends(admin_user)):
    meta("DELETE FROM datasources WHERE name = ?", (name,))
    HEALTH.pop(name, None)
    invalidate()
    return {"ok": True}


@app.get("/api/catalog")
def catalog(user=Depends(current_user)):
    key, db = engine(user)
    if key not in CATALOG:  # cached until a datasource changes or someone hits refresh
        rows = db.cursor().execute(
            "SELECT database_name, schema_name, table_name, column_name, data_type FROM duckdb_columns()"
            " WHERE NOT internal AND database_name NOT IN ('system', 'temp') ORDER BY ALL").fetchall()
        CATALOG[key] = [dict(zip(("database", "schema", "table", "column", "type"), r)) for r in rows]
    return CATALOG[key]


@app.post("/api/catalog/refresh")
def refresh_catalog(_=Depends(current_user)):
    invalidate()  # next query re-attaches every source, picking up new tables/columns
    return {"ok": True}


def start(q, user):
    """Run q in the user's engine. Returns the open cursor; caller must call finish()."""
    cur = engine(user)[1].cursor()
    RUNNING[q.id] = (user["email"], cur)
    timer = threading.Timer(TIMEOUT_S, cur.interrupt)
    timer.start()
    try:
        # allowed_directories also permits writes, so file-writing statements are refused outright.
        if {s.type for s in cur.extract_statements(q.sql)} & FILE_WRITES:
            raise duckdb.PermissionException("COPY / EXPORT are not allowed")
        cur.execute(q.sql)
    except duckdb.Error as e:
        finish(q, user, cur, timer, error=e)
    return cur, timer


def finish(q, user, cur, timer, rows=None, error=None):
    timer.cancel()
    RUNNING.pop(q.id, None)
    cur.close()
    meta("INSERT INTO history(id, email, sql, status, rows, error) VALUES (?, ?, ?, ?, ?, ?)",
         (q.id, user["email"], q.sql, "FAILED" if error else "SUCCESS", rows, error and str(error)))
    if error:
        raise HTTPException(400, f"{type(error).__name__}: {error}")


@app.post("/api/query")
def run_query(q: Query, user=Depends(current_user)):
    cur, timer = start(q, user)
    try:
        cols = [d[0] for d in cur.description or []]
        rows = cur.fetchmany(q.limit) if cols else []
    except duckdb.Error as e:
        finish(q, user, cur, timer, error=e)
    finish(q, user, cur, timer, rows=len(rows))
    return {"columns": cols, "rows": rows, "truncated": len(rows) == q.limit}


@app.post("/api/export")
def export(q: Query, format: str = "csv", user=Depends(current_user)):
    """Stream the full result (no row limit) as CSV or NDJSON without holding it in memory."""
    if format not in ("csv", "ndjson"):
        raise HTTPException(400, "format must be csv or ndjson")
    cur, timer = start(q, user)
    cols = [d[0] for d in cur.description or []]

    def stream():
        n, err = 0, None
        buf = io.StringIO()
        out = csv.writer(buf)
        try:
            if format == "csv":
                out.writerow(cols)
            while batch := cur.fetchmany(10_000):
                n += len(batch)
                if format == "csv":
                    out.writerows(batch)
                else:
                    buf.writelines(json.dumps(dict(zip(cols, r)), default=str) + "\n" for r in batch)
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()
        except duckdb.Error as e:
            err = e
        try:
            finish(q, user, cur, timer, rows=n, error=err)
        except HTTPException:
            yield f"\n# export failed after {n} rows: {err}\n"

    ext = {"csv": ("text/csv", "csv"), "ndjson": ("application/x-ndjson", "ndjson")}[format]
    return StreamingResponse(stream(), media_type=ext[0],
                             headers={"Content-Disposition": f'attachment; filename="ducktale-export.{ext[1]}"'})


@app.post("/api/query/{qid}/cancel")
def cancel_query(qid: str, user=Depends(current_user)):
    owner, cur = RUNNING.get(qid, (None, None))
    if cur and (owner == user["email"] or user["admin"]):
        cur.interrupt()
        return {"cancelled": True}
    return {"cancelled": False}


@app.get("/api/history")
def history(offset: int = 0, limit: int = 20, user=Depends(current_user)):
    rows = meta("SELECT id, sql, status, rows, error, at FROM history WHERE email = ?"
                " ORDER BY at DESC, rowid DESC LIMIT ? OFFSET ?", (user["email"], min(limit, 100), max(offset, 0)))
    return {"total": meta("SELECT count(*) FROM history WHERE email = ?", (user["email"],))[0][0],
            "items": [dict(zip(("id", "sql", "status", "rows", "error", "at"), r)) for r in rows]}


@app.get("/api/saved")
def list_saved(user=Depends(current_user)):
    rows = meta("SELECT id, name, sql, updated_at FROM saved_queries WHERE owner = ? ORDER BY name", (user["email"],))
    return [dict(zip(("id", "name", "sql", "updated_at"), r)) for r in rows]


@app.post("/api/saved")
def save_query(s: SavedQuery, user=Depends(current_user)):
    if not s.name.strip():
        raise HTTPException(400, "name required")
    meta("INSERT INTO saved_queries(owner, name, sql) VALUES (?, ?, ?) ON CONFLICT(owner, name)"
         " DO UPDATE SET sql = excluded.sql, updated_at = CURRENT_TIMESTAMP", (user["email"], s.name.strip(), s.sql))
    return {"ok": True}


@app.delete("/api/saved/{sid}")
def delete_saved(sid: int, user=Depends(current_user)):
    meta("DELETE FROM saved_queries WHERE id = ? AND owner = ?", (sid, user["email"]))
    return {"ok": True}
