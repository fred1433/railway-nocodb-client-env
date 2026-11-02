"""Replay witness. Before a replay, insert one row the seed cannot recreate; after it, require that row and the
sample rows to be unchanged. A replay that truncated and reseeded would give the same seed rows, but not the sentinel.

    SENTINEL_ACTION=insert   insert the row, report the sample-table state with it
    SENTINEL_ACTION=check    report whether the row is still there and the state now, then remove the row
"""
import os
from common import connect, die, emit, table_state, wait_for_postgres

E = os.environ
ACTION, VALUE = E.get("SENTINEL_ACTION", ""), E.get("SENTINEL", "")
ACCOUNT_NO = 990001
if ACTION not in ("insert", "check") or len(VALUE) < 8:
    die("sentinel", "SENTINEL_ACTION must be insert or check, SENTINEL an id of 8 characters or more")
emit("JOB_START", job="sentinel", action=ACTION)
wait_for_postgres("client_loader", E["LOADER_PASSWORD"], "client_data")
with connect("client_loader", E["LOADER_PASSWORD"], "client_data") as conn:
    if ACTION == "insert":
        conn.execute("insert into accounts (account_no, name, kind) values (%s, %s, 'asset')", (ACCOUNT_NO, "replay sentinel " + VALUE))
        emit("JOB_RESULT", ok=True, job="sentinel", action="insert", rows=table_state(conn))
    else:
        found = conn.execute("select count(*) from accounts where account_no=%s and name=%s", (ACCOUNT_NO, "replay sentinel " + VALUE)).fetchone()[0]
        rows = table_state(conn)
        conn.execute("delete from accounts where account_no=%s and name=%s", (ACCOUNT_NO, "replay sentinel " + VALUE))
        emit("JOB_RESULT", ok=found == 1, job="sentinel", action="check", sentinel_found=found, rows=rows)
