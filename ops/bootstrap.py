"""Idempotent bootstrap. Waits for its dependencies, fails clearly, and leaves data alone on a replay."""
import hashlib, json, os, time
from psycopg import sql
from common import APP_ROOT, PGHOST, PGPORT, SAMPLE_TABLES, NocoDB, connect, die, emit, table_state, wait_for_postgres

E = os.environ
CLIENT_DB = "client_data"
META_DB = "nocodb_meta"
ROLES = {
    "client_loader": (E["LOADER_PASSWORD"], "NOINHERIT"),
    "nocodb_meta_owner": (E["NC_META_PASSWORD"], "NOINHERIT"),
    "nocodb_reader": (E["NC_READER_PASSWORD"], "NOINHERIT"),
    "backup_runner": (E["BACKUP_PASSWORD"], "INHERIT"),
}
EXPECTED_TABLES = SAMPLE_TABLES
created = []


def ensure_roles(cur):
    for name, (password, inherit) in ROLES.items():
        exists = cur.execute("select 1 from pg_roles where rolname=%s", (name,)).fetchone()
        verb = "ALTER" if exists else "CREATE"
        cur.execute(sql.SQL(verb + " ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE " + inherit + " PASSWORD {}").format(
            sql.Identifier(name), sql.Literal(password)))
        if not exists:
            created.append("role:" + name)
    cur.execute("GRANT pg_read_all_data TO backup_runner")


def ensure_databases(cur):
    for db, owner in ((CLIENT_DB, "client_loader"), (META_DB, "nocodb_meta_owner")):
        if not cur.execute("select 1 from pg_database where datname=%s", (db,)).fetchone():
            cur.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(db), sql.Identifier(owner)))
            created.append("database:" + db)
        cur.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(db)))
    cur.execute(f"GRANT CONNECT ON DATABASE {CLIENT_DB} TO nocodb_reader, backup_runner")
    cur.execute(f"GRANT CONNECT ON DATABASE {META_DB} TO backup_runner")


def lock_client_schema():
    with connect("owner", E["POSTGRES_PASSWORD"], CLIENT_DB) as conn:
        conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        conn.execute("GRANT USAGE, CREATE ON SCHEMA public TO client_loader")
        conn.execute("GRANT USAGE ON SCHEMA public TO nocodb_reader, backup_runner")
        conn.execute("ALTER DEFAULT PRIVILEGES FOR ROLE client_loader IN SCHEMA public GRANT SELECT ON TABLES TO nocodb_reader")


def seed():
    with open(os.path.join(APP_ROOT, "reference/seed.sql")) as fh:
        script = fh.read()
    with connect("client_loader", E["LOADER_PASSWORD"], CLIENT_DB) as conn:
        for statement in [s.strip() for s in script.split(";\n") if s.strip()]:
            clean = "\n".join(l for l in statement.splitlines() if not l.startswith("--")).strip()
            if clean:
                conn.execute(clean, {"client_id": E["CLIENT_ID"], "marker": E["CLIENT_MARKER"]} if "%(" in clean else None)
    with connect("owner", E["POSTGRES_PASSWORD"], CLIENT_DB) as conn:
        conn.execute("GRANT SELECT ON ALL TABLES IN SCHEMA public TO nocodb_reader")


def close_signup(nc):
    """NC_INVITE_ONLY_SIGNUP=true left sign-up open on 2026.10.1: the admin setting is what the server reads.
    This runs before cloudflared is deployed, so the instance is never reachable with sign-up open."""
    settings = nc.ok("GET", "/api/v1/app-settings")
    if not settings.get("invite_only_signup"):
        settings["invite_only_signup"] = True
        nc.ok("POST", "/api/v1/app-settings", settings)
        created.append("nocodb:invite_only_signup")
    if not nc.ok("GET", "/api/v1/meta/nocodb/info").get("inviteOnlySignup"):
        die("nocodb_signup", "invite-only sign-up is still off after setting it")


def ensure_nocodb():
    nc = NocoDB(E["NOCODB_URL"])
    nc.wait_ready()
    nc.signin(E["NC_ADMIN_EMAIL"], E["NC_ADMIN_PASSWORD"])
    close_signup(nc)
    bases = nc.ok("GET", "/api/v2/meta/bases")["list"]
    base = next((b for b in bases if b["title"] == "client_data"), None)
    if not base:
        base = nc.ok("POST", "/api/v2/meta/bases", {"title": "client_data"})
        created.append("nocodb:base")
    base_id = base["id"]
    sources = nc.ok("GET", f"/api/v2/meta/bases/{base_id}/sources")["list"]
    if not any(s.get("alias") == "client_data_ro" for s in sources):
        nc.ok("POST", f"/api/v2/meta/bases/{base_id}/sources", {
            "alias": "client_data_ro", "type": "pg", "is_schema_readonly": True, "is_data_readonly": True,
            "inflection_column": "none", "inflection_table": "none",
            "config": {"client": "pg", "connection": {
                "host": PGHOST, "port": PGPORT, "user": "nocodb_reader",
                "password": E["NC_READER_PASSWORD"], "database": CLIENT_DB, "ssl": False},
                "searchPath": ["public"]}})
        created.append("nocodb:source")
    deadline = time.time() + 120
    titles = []
    while time.time() < deadline:
        tables = nc.ok("GET", f"/api/v2/meta/bases/{base_id}/tables")["list"]
        titles = sorted(t["table_name"] for t in tables)
        if all(name in titles for name in EXPECTED_TABLES):
            return {"base": base_id, "tables": titles}
        time.sleep(3)
    die("nocodb_source", f"source has {len(titles)} tables, expected {EXPECTED_TABLES}")


def snapshot(nocodb_state):
    state = {}
    with connect("owner", E["POSTGRES_PASSWORD"], "postgres") as conn:
        state["roles"] = [list(r) for r in conn.execute(
            "select rolname, rolcanlogin, rolsuper from pg_roles where rolname !~ '^pg_' order by 1").fetchall()]
        state["databases"] = [r[0] for r in conn.execute(
            "select datname from pg_database where not datistemplate order by 1").fetchall()]
    with connect("owner", E["POSTGRES_PASSWORD"], CLIENT_DB) as conn:
        state["rows"] = table_state(conn)
    state["nocodb"] = nocodb_state
    digest = hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()
    emit("STATE", digest=digest, state=state)
    return digest


started = time.time()
emit("JOB_START", job="bootstrap", client=E["CLIENT_ID"])
wait_for_postgres("owner", E["POSTGRES_PASSWORD"])
try:
    with connect("owner", E["POSTGRES_PASSWORD"], "postgres") as conn:
        ensure_roles(conn)
        ensure_databases(conn)
    lock_client_schema()
    seed()
except Exception as exc:  # the message names the failing statement, never a password
    die("database", type(exc).__name__ + ": " + str(exc).splitlines()[0])
emit("DB_PHASE", ok=True, created=list(created))
nocodb_state = ensure_nocodb()
digest = snapshot(nocodb_state)
emit("JOB_RESULT", ok=True, job="bootstrap", created=created, state_digest=digest, seconds=round(time.time() - started))
