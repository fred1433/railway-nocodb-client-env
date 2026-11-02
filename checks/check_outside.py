#!/usr/bin/env python3
"""Checks run from the public internet against one hostname behind Cloudflare Access. Standard library only.

    OWN_ID=... OWN_SECRET=... PEER_ID=... PEER_SECRET=... python3 check_outside.py railway-check-a.example.com
    add --origin-stopped when NocoDB is not running: the own token must then pass Access and reach a dead tunnel.

OWN is the service token in this application's policy. PEER is another client's valid token, which must be refused.
OTHER (optional) is a token that belongs to no policy. A refusal counts only when Access itself answers: HTTP 403
with the Cf-Access-Domain header of this host, or a redirect to a cloudflareaccess.com login. A 502 is not a refusal.
"""
import json, os, sys, urllib.error, urllib.parse, urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(NoRedirect)


def fetch(host, path, token=None):
    headers = {"User-Agent": "client-env-checks/1"}
    if token:
        headers.update({"CF-Access-Client-Id": token[0], "CF-Access-Client-Secret": token[1]})
    req = urllib.request.Request(f"https://{host}{path}", headers=headers)
    try:
        resp = opener.open(req, timeout=30)
        return resp.status, resp.headers, resp.read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read(400).decode("utf-8", "replace")


def classify(host, status, headers, body):
    """Who answered: Access, NocoDB, or Cloudflare for an unreachable origin."""
    domain = (headers.get("Cf-Access-Domain") or "").lower()
    location = urllib.parse.urlparse(headers.get("Location") or "").hostname or ""
    if status == 403 and domain == host.lower():
        return "access_refused", "refused by Cloudflare Access"
    if status in (301, 302, 303, 307) and location.endswith(".cloudflareaccess.com"):
        return "access_refused", "redirected to the Cloudflare Access login"
    if status == 200 and '"uptime"' in body:
        return "nocodb", "served by NocoDB"
    if status in (502, 503, 504, 530) and body.startswith("error code: "):
        return "origin_down", "passed Access, Cloudflare reports the tunnel origin down (" + body.strip()[:20] + ")"
    if status in (502, 503, 504, 530):
        return "origin_down", "passed Access, origin unreachable"
    return "other", "answered by something other than Access"


def run(host, own, peer=None, other=None, origin_running=True):
    out = []

    def check(cid, expected, status, verdict, ok, cmd):
        out.append({"id": cid, "expected": expected, "observed": f"HTTP {status}, {verdict}", "ok": bool(ok), "cmd": cmd})

    def probe(token, path="/api/v1/health"):
        status, headers, body = fetch(host, path, token)
        kind, verdict = classify(host, status, headers, body)
        return status, kind, verdict, body

    status, kind, verdict, _ = probe(None)
    check("web.anonymous", "refused by Access", status, verdict, kind == "access_refused", f"GET https://{host}/api/v1/health, no token")
    status, kind, verdict, body = probe(own)
    if origin_running:
        check("web.allowed", "this client's service token passes Access and NocoDB answers", status, verdict, kind == "nocodb",
              "same request with this client's service token")
    else:
        check("web.allowed", "this client's service token passes Access (NocoDB stopped, so the tunnel origin is down)", status, verdict,
              kind == "origin_down", "same request with this client's service token, NocoDB stopped")
    if peer:
        status, kind, verdict, _ = probe(peer)
        check("web.peer", "the other client's valid service token is refused by Access", status, verdict, kind == "access_refused",
              "same request with the other client's service token")
    if other:
        status, kind, verdict, _ = probe(other)
        check("web.other", "a token in no policy is refused by Access (same answer as an invalid token)", status, verdict,
              kind == "access_refused", "same request with a token that belongs to no policy")
    if origin_running:
        status, _, body = fetch(host, "/api/v2/meta/bases", own)
        check("web.second_login", "NocoDB still asks for its own login after Access", status,
              "NocoDB login required" if status == 401 else "no NocoDB login asked", status == 401,
              "GET /api/v2/meta/bases with this client's service token, no NocoDB session")
    return out


if __name__ == "__main__":
    E = os.environ
    pair = lambda prefix: (E[prefix + "_ID"], E[prefix + "_SECRET"]) if E.get(prefix + "_ID") else None
    host = next(a for a in sys.argv[1:] if not a.startswith("--"))
    results = run(host, pair("OWN"), pair("PEER"), pair("OTHER"), origin_running="--origin-stopped" not in sys.argv)
    print(json.dumps(results, indent=1))
    sys.exit(0 if all(r["ok"] for r in results) else 1)
