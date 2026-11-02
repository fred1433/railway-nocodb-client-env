"""check_outside.py with canned answers: a refusal counts only when Access itself answers."""
import os, sys

from fakes import ROOT

sys.path.insert(0, os.path.join(ROOT, "checks"))
import check_outside  # noqa: E402

HOST = "railway-check-a.example.com"
OWN, PEER = ("own.access", "s1"), ("peer.access", "s2")
ACCESS_403 = (403, {"Cf-Access-Domain": HOST, "Content-Type": "text/html"}, "<title>Error ・ Cloudflare Access</title>")
NOCODB_200 = (200, {}, '{"message":"OK","timestamp":1,"uptime":2.5}')
BAD_GATEWAY = (502, {}, "Bad gateway")


def answering(table):
    def fetch(host, path, token=None):
        return table.get((token, path), table.get(token))
    return fetch


def results(monkeypatch, table, *tokens):
    monkeypatch.setattr(check_outside, "fetch", answering(table))
    return {c["id"]: c for c in check_outside.run(HOST, *tokens)}


def test_access_answers_pass(monkeypatch):
    out = results(monkeypatch, {None: ACCESS_403, OWN: NOCODB_200, PEER: ACCESS_403,
                                (OWN, "/api/v2/meta/bases"): (401, {}, '{"error":"ERR_AUTHENTICATION_REQUIRED"}')}, OWN, PEER)
    assert all(c["ok"] for c in out.values()), out


def test_a_502_is_not_a_refusal(monkeypatch):
    out = results(monkeypatch, {None: BAD_GATEWAY, OWN: NOCODB_200, PEER: BAD_GATEWAY,
                                (OWN, "/api/v2/meta/bases"): (401, {}, "{}")}, OWN, PEER)
    assert out["web.anonymous"]["ok"] is False
    assert not any(c["ok"] for c in out.values() if c["id"] in ("web.peer", "web.other"))


def test_a_403_from_the_origin_is_not_an_access_refusal(monkeypatch):
    origin_403 = (403, {"Content-Type": "application/json"}, '{"error":"ERR_FORBIDDEN"}')
    out = results(monkeypatch, {None: origin_403, OWN: NOCODB_200, PEER: origin_403,
                                (OWN, "/api/v2/meta/bases"): (401, {}, "{}")}, OWN, PEER)
    assert out["web.anonymous"]["ok"] is False


def test_own_token_with_origin_stopped_must_reach_the_dead_tunnel(monkeypatch):
    monkeypatch.setattr(check_outside, "fetch", answering({None: ACCESS_403, OWN: (530, {}, "error code: 1033"), PEER: ACCESS_403}))
    out = {c["id"]: c for c in check_outside.run(HOST, OWN, PEER, origin_running=False)}
    assert out["web.allowed"]["ok"] and out["web.peer"]["ok"]
    monkeypatch.setattr(check_outside, "fetch", answering({None: ACCESS_403, OWN: ACCESS_403, PEER: ACCESS_403}))
    out = {c["id"]: c for c in check_outside.run(HOST, OWN, PEER, origin_running=False)}
    assert out["web.allowed"]["ok"] is False
