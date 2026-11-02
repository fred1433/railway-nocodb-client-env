"""Local stand-ins for the tests: a Postgres 18 cluster, a fake NocoDB, a fake backup sink, a fake Railway API.
Nothing here talks to Railway or Cloudflare. Servers listen on 127.0.0.1 only."""
import json, os, re, shutil, socket, subprocess, sys, tempfile, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psycopg

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PG_BIN = os.environ.get("PG_BIN") or next((d for d in ("/opt/homebrew/opt/postgresql@18/bin", "/usr/lib/postgresql/18/bin")
                                           if os.path.exists(os.path.join(d, "postgres"))), "")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Cluster:
    """A throwaway Postgres cluster, superuser `owner`, TCP on 127.0.0.1 only, no Unix socket."""

    def __init__(self, password="owner-local-test"):
        self.dir = tempfile.mkdtemp(prefix="pg-")
        self.port, self.password = free_port(), password
        pwfile = os.path.join(self.dir, "pw")
        open(pwfile, "w").write(password)
        subprocess.run([os.path.join(PG_BIN, "initdb"), "-D", os.path.join(self.dir, "data"), "-U", "owner", "--pwfile", pwfile,
                        "-A", "scram-sha-256", "--locale=en_US.UTF-8"], check=True, capture_output=True)
        subprocess.run([os.path.join(PG_BIN, "pg_ctl"), "-D", os.path.join(self.dir, "data"), "-l", os.path.join(self.dir, "log"), "-w",
                        "-o", f"-p {self.port} -c listen_addresses=127.0.0.1 -c unix_socket_directories=''", "start"], check=True, capture_output=True)

    def env(self):
        return {"PGHOST": "127.0.0.1", "PGPORT": str(self.port), "POSTGRES_PASSWORD": self.password}

    def sql(self, statement, db="postgres", user="owner", password=None):
        with psycopg.connect(host="127.0.0.1", port=self.port, user=user, password=password or self.password, dbname=db, autocommit=True) as c:
            cur = c.execute(statement)
            return cur.fetchall() if cur.description else None

    def stop(self):
        subprocess.run([os.path.join(PG_BIN, "pg_ctl"), "-D", os.path.join(self.dir, "data"), "-m", "immediate", "stop"], capture_output=True)
        shutil.rmtree(self.dir, ignore_errors=True)


class _Server(ThreadingHTTPServer):
    daemon_threads = True


def serve(handler_cls, **state):
    server = _Server(("127.0.0.1", 0), handler_cls)
    server.state = state
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body):
        raw = json.dumps(body).encode() if not isinstance(body, bytes) else body
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""


class NocoDBHandler(_Handler):
    """Enough of the NocoDB API for bootstrap.py and check_inside.py. Tables and records come from Postgres through the
    source's own connection settings. mode="writable": the source accepts writes, so a write gets a validation 400,
    and sign-up is open but the probe gets a validation 400."""

    def route(self, method):
        st = self.server.state
        url = urllib.parse.urlparse(self.path)
        path = url.path
        authed = self.headers.get("xc-auth") == "fake-token"
        if path == "/api/v1/health":
            return self.reply(200, {"message": "OK", "timestamp": int(time.time() * 1000), "uptime": 1.5})
        if path == "/api/v1/auth/user/signin" and method == "POST":
            body = json.loads(self.body() or b"{}")
            if body.get("email") == st["admin_email"] and body.get("password") == st["admin_password"]:
                return self.reply(200, {"token": "fake-token"})
            return self.reply(401, {"msg": "Invalid credentials"})
        if path == "/api/v1/auth/user/signup" and method == "POST":
            self.body()
            if st["invite_only"]:
                return self.reply(400, {"msg": "Not allowed to signup, contact super admin. If you are the admin, invite this user instead."})
            return self.reply(400, {"msg": "Invalid email domain"})
        if not authed:
            return self.reply(401, {"error": "ERR_AUTHENTICATION_REQUIRED", "message": "Authentication required"})
        if path == "/api/v1/app-settings":
            if method == "POST":
                st["invite_only"] = bool(json.loads(self.body()).get("invite_only_signup"))
            return self.reply(200, {"invite_only_signup": st["invite_only"]})
        if path == "/api/v1/meta/nocodb/info":
            return self.reply(200, {"inviteOnlySignup": st["invite_only"]})
        if path == "/api/v1/version":
            return self.reply(200, {"currentVersion": "2026.10.1"})
        if path == "/api/v1/users":
            return self.reply(200, {"pageInfo": {"totalRows": st["users"]}})
        if path == "/api/v2/meta/bases":
            if method == "POST":
                base = {"id": "b1", "title": json.loads(self.body())["title"]}
                st["bases"].append(base)
                return self.reply(200, base)
            return self.reply(200, {"list": st["bases"]})
        m = re.fullmatch(r"/api/v2/meta/bases/(\w+)/sources", path)
        if m:
            if method == "POST":
                st["sources"].append(json.loads(self.body()))
            return self.reply(200, {"list": [{"alias": s["alias"]} for s in st["sources"]]})
        m = re.fullmatch(r"/api/v2/meta/bases/(\w+)/tables", path)
        if m:
            names = [r[0] for r in self.pg("select table_name from information_schema.tables where table_schema='public' order by 1")] if st["sources"] else []
            return self.reply(200, {"list": [{"id": "t_" + n, "table_name": n} for n in names]})
        m = re.fullmatch(r"/api/v2/tables/t_(\w+)/records", path)
        if m and method == "GET":
            cur_rows = self.pg(f"select row_to_json(x) from {m.group(1)} x limit 5")
            return self.reply(200, {"list": [r[0] for r in cur_rows]})
        if m and method == "POST":
            self.body()
            if st["mode"] == "readonly" and st["sources"] and st["sources"][0].get("is_data_readonly"):
                return self.reply(403, {"error": "ERR_FORBIDDEN", "message": "Forbidden - Source 'client_data_ro' is read-only"})
            return self.reply(400, {"error": "ERR_DATABASE_OP_FAILED", "message": "column kind: invalid input"})
        return self.reply(404, {"msg": "not found " + path})

    def pg(self, statement):
        c = self.server.state["sources"][0]["config"]["connection"]
        with psycopg.connect(host=c["host"], port=c["port"], user=c["user"], password=c["password"], dbname=c["database"], autocommit=True) as conn:
            return conn.execute(statement).fetchall()

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")


def fake_nocodb(admin_email, admin_password, mode="readonly"):
    return serve(NocoDBHandler, admin_email=admin_email, admin_password=admin_password, invite_only=False, bases=[], sources=[],
                 users=1, mode=mode)


class SinkHandler(_Handler):
    """The sink contract: PUT with the write token adds an object once (201, then 409), GET with the read token lists or reads."""

    def tokens(self, client):
        return self.server.state["tokens"].get(client, {})

    def parse(self):
        m = re.fullmatch(r"/([a-z0-9-]+)/([A-Za-z0-9._-]*)", urllib.parse.urlparse(self.path).path)
        bearer = (self.headers.get("Authorization") or "").replace("Bearer ", "")
        return m, bearer

    def do_PUT(self):
        m, bearer = self.parse()
        body = self.body()
        if not m or not m.group(2) or bearer != self.tokens(m.group(1)).get("write"):
            return self.reply(403, b"forbidden")
        key = m.group(1) + "/" + m.group(2)
        with self.server.state["lock"]:
            if key in self.server.state["objects"]:
                return self.reply(409, b"exists")
            self.server.state["objects"][key] = body
        self.reply(201, b"stored")

    def do_GET(self):
        m, bearer = self.parse()
        if not m or bearer != self.tokens(m.group(1)).get("read"):
            return self.reply(403, b"forbidden")
        objects = self.server.state["objects"]
        if not m.group(2):
            keys = sorted(k for k in objects if k.startswith(m.group(1) + "/"))
            return self.reply(200, {"keys": keys, "sizes": [len(objects[k]) for k in keys]})
        key = m.group(1) + "/" + m.group(2)
        return self.reply(200, objects[key]) if key in objects else self.reply(404, b"not found")


def fake_sink(tokens):
    return serve(SinkHandler, tokens=tokens, objects={}, lock=threading.Lock())


def run_job(script, env, cwd=ROOT):
    """Run one ops job the way the ops image does, with this checkout as /app."""
    full = {**os.environ, "APP_ROOT": ROOT, "PYTHONPATH": os.path.join(ROOT, "ops"), "PG_WAIT_SECONDS": "20", "NC_WAIT_SECONDS": "20",
            "PATH": PG_BIN + os.pathsep + os.environ.get("PATH", ""), **env}
    done = subprocess.run([sys.executable, os.path.join(ROOT, script)], env=full, cwd=cwd, capture_output=True, text=True, timeout=180)
    return done.returncode, done.stdout.splitlines(), done.stderr


def tagged(lines, tag):
    return [json.loads(l[len(tag) + 1:]) for l in lines if l.startswith(tag + " ")]


def client_env(cluster, nocodb_url, marker="acme-mech client-specific test record", client="acme-mech"):
    return {**cluster.env(), "CLIENT_ID": client, "CLIENT_MARKER": marker, "LOADER_PASSWORD": "loader-local-pw-0001",
            "NC_META_PASSWORD": "meta-local-pw-0001", "NC_READER_PASSWORD": "reader-local-pw-0001", "BACKUP_PASSWORD": "backup-local-pw-0001",
            "NOCODB_URL": nocodb_url, "NC_ADMIN_EMAIL": "admin@acme-mech.example", "NC_ADMIN_PASSWORD": "Ab1!admin-local-pw"}
