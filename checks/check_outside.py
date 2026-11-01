#!/usr/bin/env python3
"""Checks run from the public internet against one hostname behind Cloudflare Access. Standard library only.

    ALLOWED_ID=... ALLOWED_SECRET=... OTHER_ID=... OTHER_SECRET=... python3 check_outside.py railway-check-a.example.com
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


def run(host, allowed, other):
    out = []

    def check(cid, expected, observed, ok, cmd):
        out.append({"id": cid, "expected": expected, "observed": observed, "ok": bool(ok), "cmd": cmd})

    status, headers, body = fetch(host, "/api/v1/health")
    location = urllib.parse.urlparse(headers.get("Location") or "").hostname
    check("web.anonymous", "not served by NocoDB", f"HTTP {status}, Location host {location}",
          status != 200 and '"uptime"' not in body, f"GET https://{host}/api/v1/health")
    status, _, body = fetch(host, "/api/v1/health", allowed)
    check("web.allowed", "served by NocoDB (HTTP 200)", f"HTTP {status} {body[:80]}", status == 200 and "OK" in body,
          "same request with the allowed service token")
    status, headers, body = fetch(host, "/api/v1/health", other)
    location = urllib.parse.urlparse(headers.get("Location") or "").hostname
    check("web.other", "refused: valid token, not in the policy", f"HTTP {status}, Location host {location}",
          status != 200 and '"uptime"' not in body,
          "same request with a valid token outside the policy")
    status, _, body = fetch(host, "/api/v2/meta/bases", allowed)
    check("web.second_login", "NocoDB still asks for its own login after Access", f"HTTP {status} {body[:80]}", status == 401,
          "GET /api/v2/meta/bases with the allowed service token, no NocoDB session")
    return out


if __name__ == "__main__":
    E = os.environ
    print(json.dumps(run(sys.argv[1], (E["ALLOWED_ID"], E["ALLOWED_SECRET"]), (E["OTHER_ID"], E["OTHER_SECRET"])), indent=1))
