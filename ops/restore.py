"""Restores one named backup of SOURCE_CLIENT into this empty environment. Needs the age identity.

RESTORE_KEY names the object, for example acme-mech/20261102T155517Z.tar.age, taken from the backup run being
tested. The job never picks "the newest" key: a write token can add an object with any later name.
"""
import json, os, re, subprocess, tarfile, tempfile, time, urllib.request
from psycopg import sql
from common import PGHOST, PGPORT, connect, die, emit, http, wait_for_postgres

E = os.environ
SOURCE = E["SOURCE_CLIENT"]
key = E.get("RESTORE_KEY", "")
emit("JOB_START", job="restore", source=SOURCE, key=key)
if not re.fullmatch(re.escape(SOURCE) + r"/[0-9]{8}T[0-9]{6}Z\.tar\.age", key):
    die("key", "RESTORE_KEY must name one backup of " + SOURCE + ", like " + SOURCE + "/20261102T155517Z.tar.age")
wait_for_postgres("owner", E["POSTGRES_PASSWORD"])
base = E["BACKUP_SINK_URL"].rstrip("/")
with connect("owner", E["POSTGRES_PASSWORD"], "postgres") as conn:
    before = sorted(r[0] for r in conn.execute("select datname from pg_database where datname in ('client_data', 'nocodb_meta')").fetchall())
    roles_before = sorted(r[0] for r in conn.execute(
        "select rolname from pg_roles where rolname in ('client_loader', 'nocodb_meta_owner', 'nocodb_reader', 'backup_runner')").fetchall())
if before or roles_before:
    die("destination", f"destination is not empty: databases {before}, roles {roles_before}")
with tempfile.TemporaryDirectory() as tmp:
    enc = f"{tmp}/bundle.tar.age"
    got = subprocess.run(["curl", "-sS", "--fail", "--max-time", "120", "-H", f"Authorization: Bearer {E['BACKUP_SINK_READ_TOKEN']}",
                          "-o", enc, f"{base}/{key}"], capture_output=True, text=True)
    if got.returncode:
        die("download", f"curl exit {got.returncode} for {key}")
    with open(f"{tmp}/identity.txt", "w") as fh:
        fh.write(E["BACKUP_AGE_IDENTITY"] + "\n")
    subprocess.run(["age", "-d", "-i", f"{tmp}/identity.txt", "-o", f"{tmp}/bundle.tar", enc], check=True)
    with tarfile.open(f"{tmp}/bundle.tar") as tar:
        tar.extractall(tmp, filter="data")
    with open(f"{tmp}/manifest.json") as fh:
        manifest = json.load(fh)
    if manifest.get("client") != SOURCE or not key.endswith("/" + str(manifest.get("stamp")) + ".tar.age"):
        die("manifest", "the bundle manifest names another client or another stamp than RESTORE_KEY")
    with connect("owner", E["POSTGRES_PASSWORD"], "postgres") as conn:
        for role, password, inherit in (("client_loader", E["LOADER_PASSWORD"], "NOINHERIT"),
                                        ("nocodb_meta_owner", E["NC_META_PASSWORD"], "NOINHERIT"),
                                        ("nocodb_reader", E["NC_READER_PASSWORD"], "NOINHERIT"),
                                        ("backup_runner", E["BACKUP_PASSWORD"], "INHERIT")):
            conn.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE " + inherit + " PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(password)))
        conn.execute("GRANT pg_read_all_data TO backup_runner")
        for db, owner in (("client_data", "client_loader"), ("nocodb_meta", "nocodb_meta_owner")):
            conn.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(db), sql.Identifier(owner)))
    env = dict(E, PGPASSWORD=E["POSTGRES_PASSWORD"])
    for db in ("client_data", "nocodb_meta"):
        done = subprocess.run(["pg_restore", "-h", PGHOST, "-p", str(PGPORT), "-U", "owner", "-d", db, "--exit-on-error", f"{tmp}/{db}.dump"],
                              env=env, capture_output=True, text=True)
        if done.returncode:
            die("pg_restore_" + db, done.stderr.strip()[-250:])
    with connect("owner", E["POSTGRES_PASSWORD"], "postgres") as conn:
        # pg_dump keeps schema and table grants, not database-level ones: a new database starts open to PUBLIC.
        for db in ("client_data", "nocodb_meta"):
            conn.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(db)))
        conn.execute("GRANT CONNECT ON DATABASE client_data TO nocodb_reader, backup_runner")
        conn.execute("GRANT CONNECT ON DATABASE nocodb_meta TO backup_runner")
    with connect("owner", E["POSTGRES_PASSWORD"], "client_data") as conn:
        marker = conn.execute("select marker from client_marker where id=1").fetchone()[0]
emit("JOB_RESULT", ok=True, job="restore", key=key, backup_stamp=manifest["stamp"], marker_sql=marker,
     destination_databases_before=before, destination_roles_before=roles_before)
