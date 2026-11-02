"""Ops jobs and inside checks against a local Postgres 18 and a fake NocoDB; restore through a fake sink."""
import json, os, sys

import pytest

from fakes import PG_BIN, ROOT, Cluster, client_env, fake_nocodb, fake_sink, run_job, tagged

pytestmark = pytest.mark.skipif(not PG_BIN, reason="needs a local Postgres 18 (set PG_BIN)")
sys.path.insert(0, os.path.join(ROOT, "provision"))


@pytest.fixture(scope="module")
def env_a():
    cluster = Cluster()
    server, url = fake_nocodb("admin@acme-mech.example", "Ab1!admin-local-pw")
    env = client_env(cluster, url)
    rc, lines, err = run_job("ops/bootstrap.py", env)
    assert rc == 0, (lines[-3:], err[-500:])
    yield {"cluster": cluster, "nocodb": server, "env": env, "boot_lines": lines}
    server.shutdown()
    cluster.stop()


def inside(env_a, **extra):
    rc, lines, err = run_job("checks/check_inside.py", {**env_a["env"], **extra})
    return {c["id"]: c for c in tagged(lines, "CHECK")}, rc


def test_bootstrap_and_inside_checks_pass(env_a):
    checks, rc = inside(env_a)
    assert rc == 0, [c for c in checks.values() if not c["ok"]]
    assert {"readonly.insert", "readonly.meta", "readonly.nocodb_write", "signup.anonymous", "future.read"} <= set(checks)


def test_any_4xx_on_write_is_not_a_read_only_refusal(env_a):
    st = env_a["nocodb"].state
    st["mode"] = "writable"
    try:
        checks, rc = inside(env_a)
    finally:
        st["mode"] = "readonly"
    assert checks["readonly.nocodb_write"]["ok"] is False
    assert rc == 1


def test_validation_400_on_open_signup_is_not_a_refusal(env_a):
    st = env_a["nocodb"].state
    st["invite_only"] = False
    try:
        checks, rc = inside(env_a)
    finally:
        st["invite_only"] = True
    assert checks["signup.anonymous"]["ok"] is False


def test_meta_refusal_does_not_depend_on_server_language(env_a):
    cluster = env_a["cluster"]
    cluster.sql("alter system set lc_messages = 'fr_FR.UTF-8'")
    cluster.sql("select pg_reload_conf()")
    try:
        checks, _ = inside(env_a)
    finally:
        cluster.sql("alter system reset lc_messages")
        cluster.sql("select pg_reload_conf()")
    assert checks["readonly.meta"]["ok"] is True, checks["readonly.meta"]


def test_meta_check_still_fails_when_reader_can_connect(env_a):
    cluster = env_a["cluster"]
    cluster.sql("grant connect on database nocodb_meta to nocodb_reader")
    try:
        checks, _ = inside(env_a)
    finally:
        cluster.sql("revoke connect on database nocodb_meta from nocodb_reader")
    assert checks["readonly.meta"]["ok"] is False


class FakeRailway:
    """Deploying a service runs its job locally with the service's variables; logs are the job's stdout."""
    SCRIPTS = {"bootstrap": "ops/bootstrap.py", "sentinel": "ops/sentinel.py", "checks": "checks/check_inside.py"}

    def __init__(self, cluster, env, reset_on_replay=False):
        self.cluster, self.reset = cluster, reset_on_replay
        self.vars = {"bootstrap": {**env, "OPS_JOB": "bootstrap"}, "checks": {**env, "OPS_JOB": "checks"}}
        self.out, self.last, self.n = {}, {}, 0

    def deploy(self, sid, env):
        variables = self.vars[sid]
        if variables["OPS_JOB"] == "bootstrap" and self.reset and self.last.get(sid):
            self.cluster.sql("truncate accounts, monthly_close, client_marker", db="client_data")
        self.n += 1
        dep = f"dep-{self.n}"
        rc, lines, _ = run_job(self.SCRIPTS[variables["OPS_JOB"]], variables)
        self.out[dep], self.last[sid] = lines, dep
        return dep

    def logs(self, dep, limit=800):
        return [{"timestamp": "2026-11-02T00:00:00Z", "message": l} for l in self.out[dep]]

    def set_vars(self, pid, env, sid, variables):
        self.vars[sid].update(variables)

    def gql(self, query, variables=None):
        if "deployments(first:1" in query:
            return {"deployments": {"edges": [{"node": {"id": self.last[variables["s"]]}}]}}
        raise AssertionError("unexpected query " + query[:60])


def replay_with(env_a, monkeypatch, tmp_path, reset):
    import prove, provision as P
    fake = FakeRailway(env_a["cluster"], env_a["env"], reset_on_replay=reset)
    fake.deploy("bootstrap", "env")  # the deployment that stood the environment up
    monkeypatch.setattr(prove, "ROOT", str(tmp_path))
    monkeypatch.setattr(prove, "gql", fake.gql)
    monkeypatch.setattr(prove, "ctx", lambda name: ({"id": name}, {}, "pid", "env", {"bootstrap": "bootstrap", "checks": "checks"}))
    for name in ("deploy", "logs", "set_vars"):
        monkeypatch.setattr(P, name, getattr(fake, name))
    prove.cmd_replay("acme-mech", "testrun")
    return json.load(open(tmp_path / "runs" / "testrun" / "acme-mech" / "replay.json"))


def test_replay_that_changes_nothing_passes(env_a, monkeypatch, tmp_path):
    assert replay_with(env_a, monkeypatch, tmp_path, reset=False)["ok"] is True


def test_replay_that_truncates_and_reseeds_is_caught(env_a, monkeypatch, tmp_path):
    result = replay_with(env_a, monkeypatch, tmp_path, reset=True)
    assert result["ok"] is False


@pytest.fixture(scope="module")
def backups(env_a):
    tokens = {"acme-mech": {"write": "w-token-local-0001", "read": "r-token-local-0001"}}
    server, url = fake_sink(tokens)
    import subprocess
    out = subprocess.run(["age-keygen"], capture_output=True, text=True, check=True).stdout
    identity = next(l for l in out.splitlines() if l.startswith("AGE-SECRET-KEY-"))
    recipient = next(l.split(": ")[1] for l in out.splitlines() if "public key" in l)
    env = {**env_a["env"], "BACKUP_SINK_URL": url, "BACKUP_SINK_TOKEN": tokens["acme-mech"]["write"], "BACKUP_AGE_RECIPIENT": recipient}
    rc, lines, err = run_job("ops/backup.py", env)
    assert rc == 0, (lines[-2:], err[-400:])
    good = tagged(lines, "JOB_RESULT")[-1]["key"]
    # A later object, added with the write token the environment holds: valid name, valid encryption, other content.
    cluster = env_a["cluster"]
    import time
    time.sleep(1.2)  # backup keys are stamped to the second
    cluster.sql("update client_marker set marker = 'planted later' where id = 1", db="client_data")
    rc, lines, err = run_job("ops/backup.py", env)
    cluster.sql(f"update client_marker set marker = '{env_a['env']['CLIENT_MARKER']}' where id = 1", db="client_data")
    assert rc == 0, err[-400:]
    later = tagged(lines, "JOB_RESULT")[-1]["key"]
    objects = server.state["objects"]
    objects["acme-mech/99991231T235959Z.tar.age"] = objects.pop(later)
    yield {"url": url, "good": good, "tokens": tokens, "identity": identity}
    server.shutdown()


def restore(env_a, backups, key):
    dest = Cluster()
    try:
        e = env_a["env"]
        env = {**dest.env(), "SOURCE_CLIENT": "acme-mech", "BACKUP_SINK_URL": backups["url"], "BACKUP_SINK_READ_TOKEN": backups["tokens"]["acme-mech"]["read"],
               "BACKUP_AGE_IDENTITY": backups["identity"], **{k: e[k] for k in ("LOADER_PASSWORD", "NC_META_PASSWORD", "NC_READER_PASSWORD", "BACKUP_PASSWORD")}}
        if key:
            env["RESTORE_KEY"] = key
        rc, lines, err = run_job("ops/restore.py", env)
        return rc, (tagged(lines, "JOB_RESULT") or [{}])[-1]
    finally:
        dest.stop()


def test_restore_uses_the_named_backup_not_the_newest_name(env_a, backups):
    rc, result = restore(env_a, backups, backups["good"])
    assert rc == 0 and result.get("ok"), result
    assert result["key"] == backups["good"]
    assert result["marker_sql"] == env_a["env"]["CLIENT_MARKER"]


def test_restore_without_a_named_backup_refuses(env_a, backups):
    rc, result = restore(env_a, backups, None)
    assert rc != 0 and result.get("ok") is not True
