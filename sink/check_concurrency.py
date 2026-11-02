#!/usr/bin/env python3
"""Concurrent uploads of one new key to the deployed sink: exactly one may be stored, and its content must stay.

    python3 sink/check_concurrency.py acme-mech --run 20261101

Writes a test key under the client's prefix with that client's write token, reads it back with the read token,
then deletes it from the bucket with wrangler (the sink itself has no delete). Stores runs/<run>/sink_concurrency.json.
"""
import argparse, concurrent.futures, hashlib, json, os, subprocess, sys, time, urllib.error, urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "provision"))
import provision as P
from cloudflare_api import account_id

BUCKET = "railway-check-backups"


def call(url, token, method="GET", body=None):
    req = urllib.request.Request(url, body, method=method, headers={"Authorization": "Bearer " + token, "User-Agent": "client-env-ops/1"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("client")
    ap.add_argument("--run", default=P.default_run())
    ap.add_argument("--attempts", type=int, default=10)
    args = ap.parse_args()
    sec, _ = P.load_secrets(P.load_json(f"reference/clients/{args.client}.json"))
    base = P.sink_url(account_id())
    key = f"{args.client}/concurrency-test-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.bin"
    bodies = [f"attempt {i} {os.urandom(8).hex()}".encode() for i in range(args.attempts)]
    with concurrent.futures.ThreadPoolExecutor(args.attempts) as pool:
        codes = list(pool.map(lambda b: call(f"{base}/{key}", sec["sink_write"], "PUT", b)[0], bodies))
    status, stored = call(f"{base}/{key}", sec["sink_read"])
    winners = [i for i, c in enumerate(codes) if c == 201]
    later = call(f"{base}/{key}", sec["sink_write"], "PUT", b"later attempt")[0]
    status_after, stored_after = call(f"{base}/{key}", sec["sink_read"])
    deleted = subprocess.run(["npx", "--yes", "wrangler@4", "r2", "object", "delete", f"{BUCKET}/{key}", "--remote"],
                             cwd=os.path.dirname(os.path.abspath(__file__)), capture_output=True, text=True).returncode == 0
    gone = call(f"{base}/{key}", sec["sink_read"])[0] == 404
    data = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "run": args.run, "test_key": key, "attempts": args.attempts,
        "codes": codes, "accepted": len(winners), "refused": codes.count(409),
        "stored_matches_the_accepted_upload": status == 200 and len(winners) == 1 and stored == bodies[winners[0]],
        "later_upload": later, "content_unchanged": status_after == 200 and stored_after == stored,
        "stored_sha256": hashlib.sha256(stored).hexdigest(), "test_key_deleted": deleted and gone,
    }
    data["ok"] = (data["accepted"] == 1 and data["refused"] == args.attempts - 1 and data["stored_matches_the_accepted_upload"]
                  and later == 409 and data["content_unchanged"])
    path = os.path.join(P.ROOT, "runs", args.run, "sink_concurrency.json")
    with open(path, "w") as fh:
        fh.write(json.dumps(data, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: data[k] for k in ("codes", "accepted", "refused", "content_unchanged", "test_key_deleted", "ok")}))
    sys.exit(0 if data["ok"] else 1)


if __name__ == "__main__":
    main()
