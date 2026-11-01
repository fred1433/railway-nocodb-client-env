#!/usr/bin/env python3
"""Second environment after the Railway quota stop.

    resume_b.py witness   one serviceCreate in the partial project, then deleted. Exit 0 if accepted, 3 if the quota holds.
    resume_b.py go        remove the partial project, stand up from empty, converge the first client, run every proof.
"""
import json, os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(__file__))
import provision as P
from railway_api import gql, RailwayError

RUN = "20261101"
ROOT = P.ROOT
FILE = os.path.join(ROOT, "runs", RUN, "beacon-hvac", "up_attempts.json")
now = lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
client = P.load_json("reference/clients/beacon-hvac.json")
sec, path = P.load_secrets(client)


def witness():
    pid, env = sec["project_id"], sec["environment_id"]
    try:
        sid = gql("mutation($i:ServiceCreateInput!){serviceCreate(input:$i){id}}", {"i": {"projectId": pid, "environmentId": env, "name": "quota-witness"}})["serviceCreate"]["id"]
    except RailwayError as exc:
        print(now(), "refused:", str(exc)[:160], flush=True)
        sys.exit(3 if "service creation limit" in str(exc) else 4)
    gql("mutation($i:String!,$e:String!){serviceDelete(id:$i,environmentId:$e)}", {"i": sid, "e": env})
    print(now(), "accepted, witness deleted", flush=True)


def prove(*args):
    out = subprocess.run([sys.executable, "-W", "ignore", "provision/prove.py", *args, "--run", RUN], cwd=ROOT, capture_output=True, text=True)
    print("==", " ".join(args), "rc", out.returncode, flush=True)
    print((out.stdout + out.stderr)[-900:], flush=True)
    return out.returncode


def go():
    gql("mutation($i:String!){projectDelete(id:$i)}", {"i": sec["project_id"]})
    sec.pop("project_id"); sec.pop("environment_id", None)
    P.save_secrets(sec, path)
    time.sleep(40)
    head = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], text=True).strip()
    start = now()
    done = subprocess.run([sys.executable, "-W", "ignore", "provision/provision.py", "up", "beacon-hvac", "--run", RUN], cwd=ROOT, capture_output=True, text=True)
    text = (done.stdout + done.stderr).strip()
    attempts = json.load(open(FILE))
    attempts.append({"attempt": len(attempts) + 1, "started": start, "ended": now(), "commit": head, "exit_code": done.returncode,
                     "stopped_by": text.splitlines()[-1][:200] if done.returncode and text else None})
    with open(FILE, "w") as fh:
        json.dump(attempts, fh, indent=1)
    print(json.dumps(attempts[-1]), flush=True)
    if done.returncode:
        sys.exit(5)
    conv = subprocess.run([sys.executable, "-W", "ignore", "provision/provision.py", "up", "acme-mech", "--run", RUN], cwd=ROOT, capture_output=True, text=True)
    print("== up acme-mech rc", conv.returncode, (conv.stdout + conv.stderr)[-300:], flush=True)
    if conv.returncode:
        sys.exit(6)
    for step in (("checks", "beacon-hvac"), ("checks", "acme-mech"), ("checks", "beacon-hvac"), ("replay", "acme-mech"), ("replay", "beacon-hvac"),
                 ("outside", "acme-mech"), ("outside", "beacon-hvac"), ("cron", "acme-mech"), ("cron", "beacon-hvac"), ("restore", "acme-mech"), ("restore", "beacon-hvac"),
                 ("memory", "acme-mech"), ("memory", "beacon-hvac"), ("audit",), ("stop", "acme-mech"), ("stop", "beacon-hvac")):
        prove(*step)


{"witness": witness, "go": go}[sys.argv[1]]()
