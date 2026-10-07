"""Self-contained check: auth, per-user access, federation, sandbox, export, encryption. Run: uv run python test_app.py"""
import os
import sqlite3
import tempfile

import duckdb

tmp = tempfile.mkdtemp().replace("\\", "/")
os.environ["DUCKTALE_DB"] = f"{tmp}/meta.db"
os.makedirs(f"{tmp}/crm")
os.makedirs(f"{tmp}/erp")
duckdb.sql(f"COPY (SELECT 1 AS id, 'Ann' AS name UNION ALL SELECT 2, 'Bob') TO '{tmp}/crm/customers.csv'")
duckdb.sql(f"COPY (SELECT 1 AS customer_id, 99.5 AS amount) TO '{tmp}/erp/orders.parquet'")

from fastapi.testclient import TestClient  # noqa: E402
from app import app  # noqa: E402

admin, analyst = TestClient(app), TestClient(app)
assert admin.get("/api/me").status_code == 401
assert admin.post("/api/login", json={"email": "admin@x.io", "password": "admin-pass"}).status_code == 200  # bootstrap
assert admin.get("/api/me").json()["admin"] is True
assert admin.post("/api/login", json={"email": "admin@x.io", "password": "wrong"}).status_code == 401

add = lambda name, path: admin.post("/api/datasources", json={"name": name, "type": "files", "config": {"tables": {"t": path}}})
assert add("crm", f"{tmp}/crm/customers.csv").status_code == 200
assert add("erp", f"{tmp}/erp/orders.parquet").status_code == 200
assert add("broken", f"{tmp}/nope/x.parquet").status_code == 400  # failed test is not saved
assert [d["name"] for d in admin.get("/api/datasources").json()] == ["crm", "erp"]
assert add("crm", f"{tmp}/crm/customers.csv").status_code == 409  # adding never silently overwrites

# Editing: secrets come back masked; sending the mask back keeps the stored value.
from app import MASK, mask, unmask  # noqa: E402
stored = {"password": "s3cret", "uri": "mongodb://u:p%40ss@h:1/", "secret": {"SECRET": "k", "REGION": "eu"}}
shown = mask(stored)
assert shown == {"password": MASK, "uri": f"mongodb://u:{MASK}@h:1/", "secret": {"SECRET": MASK, "REGION": "eu"}}, shown
assert unmask(shown, stored) == stored and unmask({**shown, "password": "new"}, stored)["password"] == "new"
edit = admin.get("/api/datasources/crm").json()
assert edit["type"] == "files" and edit["config"]["tables"]["t"].endswith("customers.csv")
assert admin.post("/api/datasources", json={**edit, "replace": True}).status_code == 200
raw = sqlite3.connect(f"{tmp}/meta.db").execute("SELECT config FROM datasources").fetchall()
assert all(c.startswith("gAAAA") and tmp not in c for (c,) in raw), "configs must be encrypted at rest"

q = lambda c, sql: c.post("/api/query", json={"id": "x", "sql": sql})
r = q(admin, "SELECT name, amount FROM crm.t JOIN erp.t ON crm.t.id = erp.t.customer_id")
assert r.json()["rows"] == [["Ann", 99.5]], r.text
for bad in [f"FROM read_csv('{os.path.abspath(__file__)}')", "SET enable_external_access=true",
            "INSTALL mysql", f"ATTACH '{tmp}/x.db' AS x", f"COPY (SELECT 1) TO '{tmp}/crm/out.csv'",
            "FROM mongo_scan('mongodb://elsewhere', 'db', 'c')", "FROM postgres_scan('host=elsewhere', 'public', 't')",
            'FROM "Postgres_Query"(\'crm\', \'select 1\')', "SELECT path FROM duckdb_databases()"]:
    assert q(admin, bad).status_code == 400, bad

# Per-user datasource access is enforced by what is attached, not by the UI.
assert admin.post("/api/users", json={"email": "ana@x.io", "password": "analyst-pass", "datasources": ["crm"]}).status_code == 200
assert analyst.post("/api/login", json={"email": "ana@x.io", "password": "analyst-pass"}).status_code == 200
assert [d["name"] for d in analyst.get("/api/datasources").json()] == ["crm"]
assert q(analyst, "SELECT count(*) FROM crm.t").json()["rows"] == [[2]]
assert q(analyst, "SELECT * FROM erp.t").status_code == 400
assert analyst.post("/api/datasources", json={"name": "z", "type": "files", "config": {}}).status_code == 403
assert analyst.get("/api/history").json()["total"] == 2  # sees only own history

exp = admin.post("/api/export?format=csv", json={"id": "e", "sql": "FROM crm.t ORDER BY id"})
assert exp.text.replace("\r", "") == "id,name\n1,Ann\n2,Bob\n", exp.text
assert admin.post("/api/saved", json={"name": "people", "sql": "FROM crm.t"}).status_code == 200
assert [s["name"] for s in admin.get("/api/saved").json()] == ["people"] and analyst.get("/api/saved").json() == []
assert admin.post("/api/logout").status_code == 200 and admin.get("/api/me").status_code == 401

# Mongo schema analysis: late/sparse fields kept, int+double widened, nested docs -> STRUCT, arrays -> LIST.
from app import infer_type, merge_types, render_type  # noqa: E402
docs = [{"_id": {"$oid": "a"}, "n": 1, "geo": {"c": "IN"}, "tags": ["x"]},
        {"_id": {"$oid": "b"}, "n": 2.5, "geo": {"c": "US", "ip": "1.2.3.4"}, "at": {"$date": 1}, "late": True, "v": None}]
schema = merge_types([infer_type(d) for d in docs])
assert {k: render_type(t) for k, t in schema.items()} == {
    "_id": "VARCHAR", "n": "DOUBLE", "geo": 'STRUCT("c" VARCHAR, "ip" VARCHAR)', "tags": "VARCHAR[]",
    "at": "TIMESTAMP", "late": "BOOLEAN", "v": "VARCHAR"}, schema
print("ok")
