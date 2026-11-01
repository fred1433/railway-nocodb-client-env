"""Minimal Cloudflare API client. Token comes from CLOUDFLARE_API_TOKEN."""
import json, os, urllib.error, urllib.request

BASE = "https://api.cloudflare.com/client/v4/"


def cf(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data, method=method, headers={
        "Authorization": "Bearer " + os.environ["CLOUDFLARE_API_TOKEN"],
        "Content-Type": "application/json",
        "User-Agent": "railway-nocodb-client-env/1",
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            out = json.load(resp)
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"{method} {path.split('?')[0].rsplit('/', 1)[-1]}: HTTP {exc.code} {payload[:300]}") from exc
    if not out.get("success"):
        raise RuntimeError(f"{method} {path}: {out.get('errors')}")
    return out["result"]


def account_id():
    return cf("GET", "accounts?per_page=1")[0]["id"]


def zone_id(name):
    return cf("GET", f"zones?name={name}")[0]["id"]
