"""Self-contained check: federate two file sources, prove the sandbox holds. Run: uv run python test_app.py"""
import os
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

c = TestClient(app)
add = lambda name, path: c.post("/api/datasources", json={"name": name, "type": "files", "config": {"tables": {"t": path}}})
assert add("crm", f"{tmp}/crm/customers.csv").status_code == 200
assert add("erp", f"{tmp}/erp/orders.parquet").status_code == 200
assert add("broken", f"{tmp}/nope/x.parquet").status_code == 400  # failed test is not saved
assert [d["name"] for d in c.get("/api/datasources").json()] == ["crm", "erp"]

q = lambda sql: c.post("/api/query", json={"id": "x", "sql": sql})
r = q("SELECT name, amount FROM crm.t JOIN erp.t ON crm.t.id = erp.t.customer_id")
assert r.json()["rows"] == [["Ann", 99.5]], r.text
for bad in [f"FROM read_csv('{os.path.abspath(__file__)}')", "SET enable_external_access=true",
            "INSTALL mysql", f"ATTACH '{tmp}/x.db' AS x", f"COPY (SELECT 1) TO '{tmp}/crm/out.csv'"]:
    assert q(bad).status_code == 400, bad
h = c.get("/api/history?limit=2").json()
assert h["total"] == 6 and len(h["items"]) == 2 and h["items"][0]["sql"].startswith("COPY"), h
print("ok")
