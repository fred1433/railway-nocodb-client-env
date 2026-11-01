#!/usr/bin/env python3
"""One attempt at beacon-hvac from an empty project, recorded with its cause, then every proof if it comes up."""
import json, os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(__file__))
import provision as P
from railway_api import gql

RUN = "20261101"
ROOT = P.ROOT
FILE = os.path.join(ROOT, "runs", RUN, "beacon-hvac", "up_attempts.json")
FIRST = "ef83d3c"
now = lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
client = P.load_json("reference/clients/beacon-hvac.json")
sec, path = P.load_secrets(client)
if sec.get("project_id"):
    gql("mutation($i:String!){projectDelete(id:$i)}", {"i": sec["project_id"]})
    sec.pop("project_id"); sec.pop("environment_id", None)
    P.save_secrets(sec, path)
    time.sleep(40)
head = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], text=True).strip()
changed = subprocess.run(["git", "-C", ROOT, "diff", "--quiet", FIRST, "--", "ops", "checks/check_inside.py", "provision/provision.py", "provision/railway_api.py",
                          "provision/cloudflare_api.py", "reference"]).returncode != 0
start = now()
done = subprocess.run([sys.executable, "-W", "ignore", "provision/provision.py", "up", "beacon-hvac", "--run", RUN], cwd=ROOT, capture_output=True, text=True)
tail = (done.stdout + done.stderr).strip().splitlines()[-1][:200] if (done.stdout + done.stderr).strip() else ""
attempts = json.load(open(FILE))
attempts.append({"attempt": len(attempts) + 1, "started": start, "ended": now(), "commit": head, "exit_code": done.returncode,
                 "stopped_by": tail if done.returncode else None, "reference_changed_after": False, "reference_differs_from_first_attempt": changed})
with open(FILE, "w") as fh:
    json.dump(attempts, fh, indent=1)
print(json.dumps(attempts[-1]), flush=True)
if done.returncode:
    sys.exit(3 if "service creation limit" in tail else 4)


def prove(*args):
    out = subprocess.run([sys.executable, "-W", "ignore", "provision/prove.py", *args, "--run", RUN], cwd=ROOT, capture_output=True, text=True)
    print("==", " ".join(args), "rc", out.returncode, flush=True)
    print((out.stdout + out.stderr)[-900:], flush=True)
    return out.returncode


prove("start", "acme-mech")
for step in (("checks", "beacon-hvac"), ("checks", "acme-mech"), ("checks", "beacon-hvac"), ("replay", "acme-mech"), ("replay", "beacon-hvac"),
             ("outside", "acme-mech"), ("outside", "beacon-hvac"), ("cron", "acme-mech"), ("cron", "beacon-hvac"), ("restore", "acme-mech"), ("restore", "beacon-hvac"),
             ("memory", "acme-mech"), ("memory", "beacon-hvac"), ("audit",), ("stop", "acme-mech"), ("stop", "beacon-hvac")):
    prove(*step)
