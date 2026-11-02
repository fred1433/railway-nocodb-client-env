"""The proof driver without Railway: a fake GraphQL API, fake jobs, a scratch root for runs/ and .secrets/."""
import json, os, runpy, shutil, subprocess, sys

import pytest

from fakes import ROOT

sys.path.insert(0, os.path.join(ROOT, "provision"))
sys.path.insert(0, os.path.join(ROOT, "checks"))
import provision as P  # noqa: E402
import prove  # noqa: E402
import railway_api  # noqa: E402
import check_outside  # noqa: E402

GOOD_KEY = "acme-mech/20261102T155517Z.tar.age"


@pytest.fixture
def scratch(tmp_path, monkeypatch):
    shutil.copytree(os.path.join(ROOT, "reference"), tmp_path / "reference")
    (tmp_path / ".secrets").mkdir()
    for name in ("acme-mech", "beacon-hvac"):
        sec = {k: f"{name}-{k}-local-test-value" for k in ("postgres", "loader", "nc_meta", "nc_reader", "backup", "sink_write", "sink_read",
                                                            "nc_admin", "nc_jwt", "nc_enc", "age_recipient")}
        sec.update({"age_identity": "AGE-SECRET-KEY-1LOCALTESTONLY", "project_id": f"p-{name}", "environment_id": f"e-{name}",
                    "svc_allowed": {"id": "1", "client_id": f"{name}-own.access", "client_secret": "s1"},
                    "svc_other": {"id": "2", "client_id": f"{name}-other.access", "client_secret": "s2"}})
        json.dump(sec, open(tmp_path / ".secrets" / f"{name}.json", "w"))
    monkeypatch.setattr(P, "ROOT", str(tmp_path))
    monkeypatch.setattr(prove, "ROOT", str(tmp_path))
    return tmp_path


class FakeAPI:
    """Projects, services, variables and deployments in memory. Restore and verify jobs answer with canned results."""

    def __init__(self, restore_result=None):
        self.projects = {"p-existing": {"name": "acme-mech-restore", "services": {"diagnostic": "s-diag"}},
                         "p-acme-mech": {"name": "acme-mech", "services": {}}, "p-beacon-hvac": {"name": "beacon-hvac", "services": {}}}
        self.vars, self.deps, self.deleted, self.n = {}, {}, [], 0
        self.restore_result = restore_result or {}

    def node(self, pid):
        return {"id": pid, "name": self.projects[pid]["name"], "environments": {"edges": [{"node": {"id": "e-" + pid, "name": "production"}}]}}

    def gql(self, q, v=None):
        v = v or {}
        self.n += 1
        if "projects(workspaceId" in q:
            return {"projects": {"edges": [{"node": self.node(pid)} for pid in self.projects]}}
        if "projectCreate" in q:
            pid = f"p-new-{self.n}"
            self.projects[pid] = {"name": v["i"]["name"], "services": {}}
            return {"projectCreate": self.node(pid)}
        if "project(id:$p){services" in q:
            return {"project": {"services": {"edges": [{"node": {"id": sid, "name": n}} for n, sid in self.projects[v["p"]]["services"].items()]}}}
        if "serviceCreate" in q:
            sid = f"s-{v['i']['name']}-{self.n}"
            self.projects[v["i"]["projectId"]]["services"][v["i"]["name"]] = sid
            return {"serviceCreate": {"id": sid}}
        if "volumes{" in q:
            return {"project": {"volumes": {"edges": []}}}
        if "volumeCreate" in q:
            return {"volumeCreate": {"id": "v1"}}
        if "variableCollectionUpsert" in q:
            self.vars.setdefault(v["i"]["serviceId"], {}).update(v["i"]["variables"])
            return {"variableCollectionUpsert": True}
        if "serviceInstanceUpdate" in q:
            return {"serviceInstanceUpdate": True}
        if "serviceInstanceDeployV2" in q:
            dep = f"d-{self.n}"
            self.deps[dep] = v["s"]
            return {"serviceInstanceDeployV2": dep}
        if "deployment(id" in q:
            return {"deployment": {"id": v["d"], "status": "SUCCESS"}}
        if "deploymentLogs" in q:
            sid = self.deps[v["d"]]
            job = self.vars.get(sid, {}).get("OPS_JOB")
            if job == "restore":
                result = {"ok": True, "job": "restore", "key": self.vars[sid].get("RESTORE_KEY", "acme-mech/99991231T235959Z.tar.age"),
                          "backup_stamp": "x", "marker_sql": "m", "destination_databases_before": [], "destination_roles_before": [], **self.restore_result}
            elif job == "restore-verify":
                result = {"ok": True, "job": "restore-verify", "marker_nocodb": "m", "nocodb_version": "2026.10.1"}
            else:
                result = {"ok": True}
            return {"deploymentLogs": [{"timestamp": "2026-11-02T00:00:00Z", "message": "JOB_RESULT " + json.dumps(result)}]}
        if "projectDelete" in q:
            self.deleted.append(v["i"])
            self.projects.pop(v["i"], None)
            return {"projectDelete": True}
        raise AssertionError("unexpected query " + q[:80])


@pytest.fixture
def api(scratch, monkeypatch):
    fake = FakeAPI()
    for module in (P, prove, railway_api):
        monkeypatch.setattr(module, "gql", fake.gql)
    monkeypatch.setattr(prove, "account_id", lambda: "acct")
    monkeypatch.setattr(P, "sink_url", lambda acct: "https://sink.example.invalid")
    monkeypatch.setattr(prove.time, "sleep", lambda s: None)
    cron = scratch / "runs" / "t1" / "acme-mech"
    cron.mkdir(parents=True)
    json.dump({"result": {"ok": True, "key": GOOD_KEY}}, open(cron / "cron.json", "w"))
    return fake


def run_restore(fake):
    try:
        prove.cmd_restore("acme-mech", "t1")
    except SystemExit:
        pass
    return json.load(open(os.path.join(prove.ROOT, "runs", "t1", "acme-mech", "restore.json")))


def test_restore_never_adopts_or_deletes_an_existing_project(api):
    run_restore(api)
    assert "p-existing" in api.projects and "p-existing" not in api.deleted
    assert len(api.deleted) == 1 and api.deleted[0].startswith("p-new-")


def test_restore_restores_the_key_this_run_stored(api):
    run_restore(api)
    restore_vars = next(v for v in api.vars.values() if v.get("OPS_JOB") == "restore")
    assert restore_vars.get("RESTORE_KEY") == GOOD_KEY


def test_destination_empty_before_is_measured(api):
    api.restore_result = {"destination_databases_before": ["client_data"]}
    data = run_restore(api)
    assert data["destination_empty_before"] is False
    assert api.deleted == []


def test_create_project_refuses_an_existing_name(api, scratch):
    run = P.Run({"id": "acme-mech"}, "t1")
    with pytest.raises(SystemExit):
        P.create_project("acme-mech-restore", run)


def test_failed_outside_proof_exits_non_zero(api, scratch, monkeypatch):
    monkeypatch.setattr(check_outside, "fetch", lambda host, path, token=None: (502, {}, "Bad gateway"))
    monkeypatch.setattr(railway_api, "usage", lambda ws: {"currentUsage": 0})
    monkeypatch.setattr(sys, "argv", ["prove.py", "outside", "acme-mech", "--run", "t1"])
    with pytest.raises(SystemExit) as stop:
        runpy.run_path(os.path.join(ROOT, "provision", "prove.py"), run_name="__main__")
    assert stop.value.code not in (0, None)


def test_resume_driver_stops_at_the_first_failed_proof(api, scratch, monkeypatch):
    attempts = scratch / "runs" / "20261101" / "beacon-hvac"
    attempts.mkdir(parents=True)
    json.dump([], open(attempts / "up_attempts.json", "w"))
    calls = []

    def fake_run(cmd, **kwargs):
        if "prove.py" in " ".join(cmd):
            step = tuple(a for a in cmd[cmd.index(next(a for a in cmd if a.endswith("prove.py"))) + 1:] if not a.startswith("--") and a != "20261101")
            calls.append(step)
            return subprocess.CompletedProcess(cmd, 1 if step == ("replay", "acme-mech") else 0, "", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: "abc1234\n")
    import time
    monkeypatch.setattr(time, "sleep", lambda s: None)
    monkeypatch.setattr(sys, "argv", ["resume_b.py", "go"])
    try:
        runpy.run_path(os.path.join(ROOT, "provision", "resume_b.py"), run_name="__main__")
    except SystemExit:
        pass
    failed_at = calls.index(("replay", "acme-mech"))
    assert all(step[0] == "stop" for step in calls[failed_at + 1:]), calls[failed_at + 1:]
