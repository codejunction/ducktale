# Ducktale

One SQL workspace over many databases. Ducktale attaches PostgreSQL, SQL Server, MongoDB, Iceberg (IOMETE),
S3-compatible storage and local files to [DuckDB](https://duckdb.org), so a single query can join across them
without copying data anywhere.

```sql
SELECT c.segment, e.campaign.name, round(sum(o.amount), 2) AS revenue
FROM crm.public.customers c                                  -- PostgreSQL
JOIN lake.orders o ON o.customer_id = c.id                   -- Parquet on S3
LEFT JOIN marketing.marketing.events e ON e.customer_id = c.id -- MongoDB
GROUP BY ALL;
```

## Run

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run uvicorn app:app --port 8000
```

Open http://localhost:8000. **The first sign-in on a fresh install creates the admin account** with the email and
password you enter, so keep the server on localhost until you have signed in.

Check: `uv run python test_app.py`

| Environment variable | Default | Meaning |
|---|---|---|
| `DUCKTALE_DB` | `ducktale.db` | Metadata store (SQLite): users, datasources, history, saved queries |
| `DUCKTALE_SECRET_KEY` | generated into `ducktale.db.key` | Fernet key that encrypts datasource credentials |
| `DUCKTALE_MEMORY` | `2GB` | DuckDB memory limit per engine |
| `DUCKTALE_TIMEOUT` | `300` | Query timeout in seconds |

## Datasources

Admins add datasources from the sidebar. **Test & save** only checks the connection; attaching every database and
building the catalog then runs in the background (the catalog shows a spinner until it is ready).

| Type | Becomes | Notes |
|---|---|---|
| PostgreSQL | `name.schema.table` | Database `*` or `a, b` attaches several: `name_db.schema.table` |
| SQL Server | `name.schema.table` | Community `mssql` extension; untested |
| MongoDB | `name.database.collection` | See below |
| Iceberg / IOMETE | `name.namespace.table` | REST catalog; several warehouses `a, b` become `name_a`, `name_b`; untested |
| S3 / S3-compatible | `name.table` | Blank endpoint = AWS; any S3-compatible store via endpoint URL |
| Local files | `name.table` | Parquet, CSV, JSON by extension |

### MongoDB

Uses the [duckdb-mongo](https://github.com/stephaniewang526/duckdb-mongo) community extension.

- Every database the user may read becomes a schema and every collection a table.
- **Schema:** a collection's `{_id: "__schema", ...}` document ([format](https://github.com/stephaniewang526/duckdb-mongo#__schema-document-atlas-sql-compatibility))
  is used when present. Otherwise Ducktale analyses 10,000 random documents per collection: nested documents become
  STRUCTs (`campaign.name`), arrays become LISTs, mixed int/double become DOUBLE. Refresh (↻) re-analyses.
- **Authentication** comes from the connection URI:

| URI | Authenticates against |
|---|---|
| `mongodb://user:pass@host/?authSource=admin` | `admin` |
| `mongodb://user:pass@host/shop` | `shop` (the path database, MongoDB's default) |
| `mongodb://user:pass@host/` | `admin` |
| `mongodb://user:pass@host/shop?authSource=%24external&authMechanism=PLAIN&tls=true` | LDAP (`$external`, PLAIN). Use TLS: PLAIN sends the password as is |
| `mongodb+srv://user:pass@cluster.mongodb.net/` | Atlas (SRV) |

`authSource` only decides where the password is checked; discovery still lists every database the user can read.
`tls`, `tlsCAFile` and `tlsAllowInvalidCertificates` map to the extension's secret fields; all other options
(`authMechanism`, `replicaSet`, `readPreference`, `appName`, ...) are passed through. Not supported: multi-host URIs
(use `mongodb+srv://`), X.509, Kerberos and AWS IAM authentication.

## Security model

- Email/password login (PBKDF2), HTTP-only session cookie; admins manage users and datasources.
- Users are granted datasources; ungranted ones are never attached to their DuckDB, so DuckDB itself refuses them.
- Datasource credentials are encrypted at rest and never sent back to the browser (edits show `********`).
- DuckDB sandbox: external access off, configuration locked, file access limited to datasource paths,
  `COPY`/`EXPORT` refused, and extension functions that take their own connection string
  (`mongo_*`, `postgres_*`, `mssql_*`, ...) blocked in user SQL.
