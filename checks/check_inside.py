#!/usr/bin/env python3
"""Checks run from inside one environment's private network. Standalone: needs only psycopg and env vars,
so it can be dropped into another template without the provisioning code.

Each check prints one line: CHECK {"id","expected","observed","ok","cmd"}.
"""
import json, os, socket, sys, time, urllib.error, urllib.request
import psycopg

E = os.environ
HOST = E.get("PGHOST", "postgres.railway.internal")
PORT = int(E.get("PGPORT", "5432"))
CLIENT_DB = E.get("CLIENT_DB", "client_data")
META_DB = E.get("META_DB", "nocodb_meta")
READER = E.get("READER_USER", "nocodb_reader")
LOADER = E.get("LOADER_USER", "client_loader")
NOCODB = E["NOCODB_URL"].rstrip("/")
TABLES = sorted(E.get("EXPECTED_TABLES", "accounts,client_marker,monthly_close").split(","))
results = []


def check(cid, expected, observed, ok, cmd):
    rec = {"id": cid, "expected": expected, "observed": observed, "ok": bool(ok), "cmd": cmd}
    results.append(rec)
    print("CHECK " + json.dumps(rec, sort_keys=True, default=str), flush=True)


def conn(user, password, db):
    return psycopg.connect(host=HOST, port=PORT, user=user, password=password, dbname=db, autocommit=True, connect_timeout=10)


def sqlstate_of(fn):
    try:
        fn()
        return None, "no error"
    except psycopg.Error as exc:
        return exc.sqlstate, str(exc).strip().splitlines()[0][:140]


def http(method, path, body=None, token=None):
    hdrs = {"Content-Type": "application/json", "User-Agent": "client-env-checks/1"}
    if token:
        hdrs["xc-auth"] = token
    req = urllib.request.Request(NOCODB + path, json.dumps(body).encode() if body is not None else None, hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw.decode("utf-8", "replace")[:200]


def resolve(name):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(name, None)}), None
    except socket.gaierror as exc:
        return [], str(exc)


def tcp(addr, port, timeout=5):
    try:
        with socket.create_connection((addr, port), timeout=timeout):
            return "connected"
    except OSError as exc:
        return type(exc).__name__ + ": " + str(exc)[:60]


def nocodb_checks():
    status, out = http("POST", "/api/v1/auth/user/signin", {"email": E["NC_ADMIN_EMAIL"], "password": E["NC_ADMIN_PASSWORD"]})
    token = out.get("token") if isinstance(out, dict) else None
    check("signup.control", "admin sign-in answers 200", f"HTTP {status}", status == 200 and token, "POST /api/v1/auth/user/signin (admin)")
    if not token:
        return
    base = next(b for b in http("GET", "/api/v2/meta/bases", token=token)[1]["list"] if b["title"] == "client_data")
    tables = http("GET", f"/api/v2/meta/bases/{base['id']}/tables", token=token)[1]["list"]
    names = sorted(t["table_name"] for t in tables)
    check("source.tables", TABLES, names, all(t in names for t in TABLES), "GET /api/v2/meta/bases/{base}/tables")
    by_name = {t["table_name"]: t for t in tables}
    status, out = http("GET", f"/api/v2/tables/{by_name['client_marker']['id']}/records?limit=5", token=token)
    rows = out.get("list", []) if isinstance(out, dict) else []
    marker = rows[0].get("marker") if rows else None
    check("source.marker", E["CLIENT_MARKER"], marker, status == 200 and marker == E["CLIENT_MARKER"],
          "GET /api/v2/tables/{client_marker}/records")
    status, out = http("POST", f"/api/v2/tables/{by_name['accounts']['id']}/records",
                       {"account_no": 9999, "name": "write attempt", "kind": "asset"}, token=token)
    check("readonly.nocodb_write", "write through NocoDB refused", f"HTTP {status} {str(out)[:120]}", 400 <= status < 500,
          "POST /api/v2/tables/{accounts}/records")
    users_before = http("GET", "/api/v1/users?limit=100", token=token)
    before = users_before[1]["pageInfo"]["totalRows"] if users_before[0] == 200 else None
    email = f"anonymous-{int(time.time())}@example.invalid"
    status, out = http("POST", "/api/v1/auth/user/signup", {"email": email, "password": "Aa1!" + "probe-signup-attempt"})
    users_after = http("GET", "/api/v1/users?limit=100", token=token)
    after = users_after[1]["pageInfo"]["totalRows"] if users_after[0] == 200 else None
    check("signup.anonymous", "anonymous sign-up rejected, user count unchanged",
          f"HTTP {status} {str(out)[:120]}; users {before} -> {after}",
          400 <= status < 500 and before == after and before is not None, "POST /api/v1/auth/user/signup")


def sql_checks():
    with conn(READER, E["NC_READER_PASSWORD"], CLIENT_DB) as c:
        marker = c.execute("select marker from client_marker where id=1").fetchone()[0]
        check("readonly.select", E["CLIENT_MARKER"], marker, marker == E["CLIENT_MARKER"], "SELECT marker FROM client_marker")
        state, msg = sqlstate_of(lambda: c.execute("insert into accounts values (9998, 'x', 'asset')"))
        check("readonly.insert", "42501", f"{state} {msg}", state == "42501", "INSERT INTO accounts")
        state, msg = sqlstate_of(lambda: c.execute("create temp table t_probe(x int)"))
        check("readonly.temp", "42501", f"{state} {msg}", state == "42501", "CREATE TEMP TABLE")
    state, msg = sqlstate_of(lambda: conn(READER, E["NC_READER_PASSWORD"], META_DB).close())
    check("readonly.meta", "42501", f"{state} {msg}", state == "42501", f"connect as {READER} to {META_DB}")
    name = f"future_probe_{int(time.time())}"
    with conn(LOADER, E["LOADER_PASSWORD"], CLIENT_DB) as load:
        load.execute(f"create table {name} (id int primary key, note text)")
        load.execute(f"insert into {name} values (1, 'created after the grants')")
        try:
            with conn(READER, E["NC_READER_PASSWORD"], CLIENT_DB) as c:
                row = c.execute(f"select note from {name}").fetchone()[0]
                check("future.read", "row readable by the reader", row, row == "created after the grants",
                      f"{LOADER}: CREATE TABLE; {READER}: SELECT")
                state, msg = sqlstate_of(lambda: c.execute(f"insert into {name} values (2, 'x')"))
                check("future.write", "42501", f"{state} {msg}", state == "42501", f"{READER}: INSERT on the new table")
        finally:
            load.execute(f"drop table {name}")


def network_checks():
    own = E.get("OWN_PRIVATE_HOST")
    if own:
        addrs, err = resolve(own)
        reach = tcp(own, 8080) if addrs else err
        check("network.own", "own private host resolves and answers", {"addrs": addrs, "tcp_8080": reach}, addrs and reach == "connected",
              f"getaddrinfo {own}; connect :8080")
    peer = E.get("PEER_PRIVATE_HOST")
    if peer:
        addrs, err = resolve(peer)
        check("network.peer_dns", "peer private host does not resolve", err or addrs, not addrs, f"getaddrinfo {peer}")
    for addr in filter(None, E.get("PEER_ADDRS", "").split(",")):
        reach = tcp(addr, 8080)
        check("network.peer_addr", "peer private address not reachable", f"{addr}: {reach}", reach != "connected", f"connect {addr}:8080")


print("JOB_START " + json.dumps({"job": "checks", "client": E.get("CLIENT_ID")}), flush=True)
for section in (sql_checks, nocodb_checks, network_checks):
    try:
        section()
    except Exception as exc:
        check("section." + section.__name__, "section completes", f"{type(exc).__name__}: {str(exc)[:160]}", False, section.__name__)
failed = [r["id"] for r in results if not r["ok"]]
print("JOB_RESULT " + json.dumps({"job": "checks", "ok": not failed, "total": len(results), "failed": failed}), flush=True)
sys.exit(1 if failed else 0)
