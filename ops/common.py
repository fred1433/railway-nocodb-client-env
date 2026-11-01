"""Helpers shared by the ops jobs. Every line of output is safe to keep: no secret is ever printed."""
import json, os, sys, time, urllib.error, urllib.request
import psycopg

PGHOST = os.environ.get("PGHOST", "postgres.railway.internal")
PGPORT = int(os.environ.get("PGPORT", "5432"))
PG_WAIT_SECONDS = int(os.environ.get("PG_WAIT_SECONDS", "180"))
NC_WAIT_SECONDS = int(os.environ.get("NC_WAIT_SECONDS", "420"))


def emit(tag, **fields):
    print(tag + " " + json.dumps(fields, sort_keys=True, default=str), flush=True)


def die(stage, detail):
    emit("JOB_RESULT", ok=False, stage=stage, detail=str(detail)[:300])
    sys.exit(1)


def connect(user, password, dbname, autocommit=True, connect_timeout=10):
    return psycopg.connect(host=PGHOST, port=PGPORT, user=user, password=password, dbname=dbname,
                           autocommit=autocommit, connect_timeout=connect_timeout)


def wait_for_postgres(user, password, dbname="postgres"):
    deadline = time.time() + PG_WAIT_SECONDS
    last = None
    while time.time() < deadline:
        try:
            with connect(user, password, dbname) as conn:
                version = conn.execute("show server_version").fetchone()[0]
            emit("WAIT", dependency="postgres", ready=True, server_version=version)
            return version
        except psycopg.OperationalError as exc:
            last = str(exc).strip().splitlines()[0][:160]
            time.sleep(3)
    die("wait_postgres", f"postgres not ready after {PG_WAIT_SECONDS}s: {last}")


def http(method, url, body=None, headers=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json", "User-Agent": "client-env-ops/1"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data, hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw.decode("utf-8", "replace")[:400]


class NocoDB:
    def __init__(self, url):
        self.url = url.rstrip("/")
        self.token = None

    def wait_ready(self):
        deadline = time.time() + NC_WAIT_SECONDS
        last = None
        while time.time() < deadline:
            try:
                status, _ = http("GET", self.url + "/api/v1/health", timeout=8)
                if status == 200:
                    emit("WAIT", dependency="nocodb", ready=True)
                    return
                last = status
            except OSError as exc:
                last = str(exc)[:120]
            time.sleep(5)
        die("wait_nocodb", f"nocodb not ready after {NC_WAIT_SECONDS}s: {last}")

    def signin(self, email, password):
        status, out = http("POST", self.url + "/api/v1/auth/user/signin", {"email": email, "password": password})
        if status != 200 or not isinstance(out, dict) or "token" not in out:
            die("nocodb_signin", f"HTTP {status}")
        self.token = out["token"]

    def call(self, method, path, body=None):
        return http(method, self.url + path, body, {"xc-auth": self.token} if self.token else None, timeout=60)

    def ok(self, method, path, body=None):
        status, out = self.call(method, path, body)
        if status not in (200, 201):
            die("nocodb_call", f"{method} {path}: HTTP {status} {str(out)[:180]}")
        return out
