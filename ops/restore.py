"""Restores the newest backup of SOURCE_CLIENT into this empty environment. Needs the age identity."""
import json, os, subprocess, tarfile, tempfile, time, urllib.request
from psycopg import sql
from common import PGHOST, PGPORT, connect, die, emit, http, wait_for_postgres

E = os.environ
emit("JOB_START", job="restore", source=E["SOURCE_CLIENT"])
wait_for_postgres("owner", E["POSTGRES_PASSWORD"])
base = E["BACKUP_SINK_URL"].rstrip("/")
auth = {"Authorization": "Bearer " + E["BACKUP_SINK_READ_TOKEN"]}
status, listing = http("GET", f"{base}/{E['SOURCE_CLIENT']}/", headers=auth)
if status != 200 or not listing.get("keys"):
    die("list", f"HTTP {status} {str(listing)[:160]}")
key = sorted(listing["keys"])[-1]
with tempfile.TemporaryDirectory() as tmp:
    enc = f"{tmp}/bundle.tar.age"
    subprocess.run(["curl", "-sS", "--fail", "--max-time", "120", "-H", f"Authorization: Bearer {E['BACKUP_SINK_READ_TOKEN']}",
                    "-o", enc, f"{base}/{key}"], check=True)
    with open(f"{tmp}/identity.txt", "w") as fh:
        fh.write(E["BACKUP_AGE_IDENTITY"] + "\n")
    subprocess.run(["age", "-d", "-i", f"{tmp}/identity.txt", "-o", f"{tmp}/bundle.tar", enc], check=True)
    with tarfile.open(f"{tmp}/bundle.tar") as tar:
        tar.extractall(tmp, filter="data")
    with open(f"{tmp}/manifest.json") as fh:
        manifest = json.load(fh)
    with connect("owner", E["POSTGRES_PASSWORD"], "postgres") as conn:
        have = {r[0] for r in conn.execute("select datname from pg_database").fetchall()}
        if have & {"client_data", "nocodb_meta"}:
            die("destination", "destination is not empty")
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
    with connect("owner", E["POSTGRES_PASSWORD"], "client_data") as conn:
        marker = conn.execute("select marker from client_marker where id=1").fetchone()[0]
emit("JOB_RESULT", ok=True, job="restore", key=key, backup_stamp=manifest["stamp"], marker_sql=marker)
