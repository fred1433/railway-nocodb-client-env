"""Reads the witness row through the restored NocoDB, not through SQL."""
import os
from common import NocoDB, die, emit

E = os.environ
nc = NocoDB(E["NOCODB_URL"])
nc.wait_ready()
nc.signin(E["NC_ADMIN_EMAIL"], E["NC_ADMIN_PASSWORD"])
base = next((b for b in nc.ok("GET", "/api/v2/meta/bases")["list"] if b["title"] == "client_data"), None)
if not base:
    die("restored_base", "base client_data not found in restored metadata")
tables = nc.ok("GET", f"/api/v2/meta/bases/{base['id']}/tables")["list"]
marker_table = next((t for t in tables if t["table_name"] == "client_marker"), None)
if not marker_table:
    die("restored_table", "table client_marker not found")
rows = nc.ok("GET", f"/api/v2/tables/{marker_table['id']}/records?limit=5")["list"]
version = nc.ok("GET", "/api/v1/version")
marker = rows[0].get("marker") if rows else None
emit("JOB_RESULT", ok=marker == E["CLIENT_MARKER"], job="restore-verify", marker_nocodb=marker,
     nocodb_version=version.get("currentVersion") if isinstance(version, dict) else None,
     tables=sorted(t["table_name"] for t in tables))
