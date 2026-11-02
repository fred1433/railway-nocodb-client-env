#!/usr/bin/env python3
"""Runs the proofs against stood-up environments and stores redacted outputs under runs/<run>/.

    prove.py checks <client>     run the checks service, keep its CHECK lines
    prove.py outside <client>    Access checks from the public internet (own, other client's and no-policy tokens)
    prove.py outside-cross <client>  the same with NocoDB stopped: own token passes Access, the other client's is refused
    prove.py replay <client>     insert a sentinel row, redeploy bootstrap, require the sentinel and the sample rows unchanged
    prove.py cron <client>       let Railway trigger the backup once, verify the stored object
    prove.py restore <client> [--key K]  restore the backup named by this run's cron.json (or K) into a new project
                                 created for this attempt, read the client-specific test record through NocoDB

Every command exits 1 when its proof fails, so a driver can stop on the first failure.
    prove.py memory <client>     read the memory series of the running services
    prove.py audit               inventory, manifest, secret fingerprints, config diff
"""
import argparse, datetime as dt, hashlib, json, os, re, subprocess, sys, time, urllib.error, urllib.request
sys.path.insert(0, os.path.dirname(__file__))
import provision as P
from railway_api import gql, usage
from cloudflare_api import account_id

ROOT = P.ROOT
CLIENTS = ("acme-mech", "beacon-hvac")
SECRET_VARS = {"POSTGRES_PASSWORD", "LOADER_PASSWORD", "NC_META_PASSWORD", "NC_READER_PASSWORD", "BACKUP_PASSWORD",
               "NC_ADMIN_PASSWORD", "NC_AUTH_JWT_SECRET", "NC_CONNECTION_ENCRYPT_KEY", "TUNNEL_TOKEN", "BACKUP_SINK_TOKEN", "NC_DB"}


def all_secret_values():
    values = set()
    def walk(v):
        if isinstance(v, str):
            if len(v) >= 16 and not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f-]{27}", v):
                values.add(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
    for name in CLIENTS:
        path = os.path.join(ROOT, ".secrets", name + ".json")
        if os.path.exists(path):
            walk(json.load(open(path)))
    return sorted(values, key=len, reverse=True)


def redact(text):
    for value in all_secret_values():
        text = text.replace(value, "[redacted]")
    return re.sub(r"eyJ[A-Za-z0-9_\-]{20,}", "[redacted]", text)


def out_path(run, *parts):
    path = os.path.join(ROOT, "runs", run, *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def store(path, data, run=None):
    if run and isinstance(data, dict):
        data = {**data, "run": run}
    with open(path, "w") as fh:
        fh.write(redact(json.dumps(data, indent=1, sort_keys=True, default=str)) + "\n")


def log_lines(dep_id):
    return [l["message"].rstrip() for l in P.logs(dep_id, 2000)]


def wait_end(dep_id, tag="JOB_RESULT", seconds=420, after=None):
    deadline = time.time() + seconds
    while time.time() < deadline:
        for line in P.logs(dep_id, 2000):
            if after and line["timestamp"] < after:
                continue
            msg = line["message"].strip()
            if msg.startswith(tag + " "):
                return json.loads(msg[len(tag) + 1:])
        time.sleep(5)
    sys.exit(f"no {tag} from {dep_id[:8]} after {seconds}s")


def ctx(name):
    client = P.load_json(f"reference/clients/{name}.json")
    sec, _ = P.load_secrets(client)
    return client, sec, sec["project_id"], sec["environment_id"], P.service_ids(sec["project_id"])


def cmd_checks(name, run):
    client, sec, pid, env, ids = ctx(name)
    peer_name = next(c for c in CLIENTS if c != name)
    peer_addrs = ""
    peer_file = out_path(run, peer_name, "inside.json")
    if os.path.exists(peer_file):
        own = next((c for c in json.load(open(peer_file))["checks"] if c["id"] == "network.own"), None)
        if own and isinstance(own["observed"], dict):
            peer_addrs = ",".join(own["observed"]["addrs"])
    P.set_vars(pid, env, ids["checks"], {"PEER_PRIVATE_HOST": f"nocodb-{peer_name}.railway.internal", "PEER_ADDRS": peer_addrs})
    dep = P.deploy(ids["checks"], env)
    result = wait_end(dep)
    lines = log_lines(dep)
    checks = [json.loads(l.strip()[6:]) for l in lines if l.strip().startswith("CHECK ")]
    store(out_path(run, name, "inside.json"), {"deployment": dep, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                               "result": result, "checks": checks, "peer_addrs_tested": peer_addrs}, run)
    print(json.dumps(result))
    for c in checks:
        print(("ok  " if c["ok"] else "FAIL"), c["id"], str(c["observed"])[:110])
    return bool(result.get("ok")) and bool(checks) and all(c["ok"] for c in checks)


def service_token(sec, slot):
    return (sec[slot]["client_id"], sec[slot]["client_secret"]) if slot in sec else None


def cmd_outside(name, run, origin_running=True):
    client = P.load_json(f"reference/clients/{name}.json")
    sec, _ = P.load_secrets(client)
    peer_name = next(c for c in CLIENTS if c != name)
    peer_sec, _ = P.load_secrets(P.load_json(f"reference/clients/{peer_name}.json"))
    sys.path.insert(0, os.path.join(ROOT, "checks"))
    import check_outside
    checks = check_outside.run(client["hostname"], service_token(sec, "svc_allowed"), service_token(peer_sec, "svc_allowed"),
                               service_token(sec, "svc_other"), origin_running=origin_running)
    data = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": checks, "origin_running": origin_running,
            "peer_token_from": peer_name}
    store(out_path(run, name, "outside.json" if origin_running else "outside_cross.json"), data, run)
    for c in checks:
        print(("ok  " if c["ok"] else "FAIL"), c["id"], str(c["observed"])[:110])
    return bool(checks) and all(c["ok"] for c in checks)


def cmd_outside_cross(name, run):
    return cmd_outside(name, run, origin_running=False)


def sentinel_job(pid, env, ids, value, action):
    """The checks service runs the sentinel job once, then gets its own job back."""
    P.set_vars(pid, env, ids["checks"], {"OPS_JOB": "sentinel", "SENTINEL": value, "SENTINEL_ACTION": action})
    try:
        return wait_end(P.deploy(ids["checks"], env))
    finally:
        P.set_vars(pid, env, ids["checks"], {"OPS_JOB": "checks"})


def replay_verdict(before_state, inserted, after_state, after_result, checked):
    """No duplicate objects, no reset: nothing created, roles, databases and NocoDB objects as before, and the
    sample rows, sentinel included, unchanged across the replay."""
    same_objects = all(before_state.get(k) == after_state.get(k) for k in ("roles", "databases", "nocodb"))
    rows_kept = inserted.get("rows") is not None and inserted.get("rows") == after_state.get("rows") == checked.get("rows")
    return {"created_on_replay": after_result.get("created"), "same_objects": same_objects, "sentinel_kept": checked.get("sentinel_found") == 1,
            "sample_rows_unchanged": rows_kept,
            "ok": bool(after_result.get("ok")) and not after_result.get("created") and same_objects and rows_kept and checked.get("sentinel_found") == 1}


def cmd_replay(name, run):
    client, sec, pid, env, ids = ctx(name)
    prior = gql("query($p:String!,$e:String!,$s:String!){deployments(first:1,input:{projectId:$p,environmentId:$e,serviceId:$s}){edges{node{id}}}}",
                {"p": pid, "e": env, "s": ids["bootstrap"]})["deployments"]["edges"][0]["node"]["id"]
    before, before_state = wait_end(prior, seconds=30), wait_end(prior, tag="STATE", seconds=30)["state"]
    value = f"{run}-{hashlib.sha256(os.urandom(16)).hexdigest()[:12]}"
    inserted = sentinel_job(pid, env, ids, value, "insert")
    dep = P.deploy(ids["bootstrap"], env)
    after, after_state = wait_end(dep), wait_end(dep, tag="STATE")["state"]
    checked = sentinel_job(pid, env, ids, value, "check")
    verdict = replay_verdict(before_state, inserted, after_state, after, checked)
    data = {"before": before, "after": after, "sentinel": {"inserted": inserted, "checked": checked}, **verdict}
    store(out_path(run, name, "replay.json"), data, run)
    print(json.dumps(verdict))
    return verdict["ok"]


def sink_call(url, token, method="GET"):
    req = urllib.request.Request(url, method=method, headers={"Authorization": "Bearer " + token, "User-Agent": "client-env-ops/1"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def cmd_cron(name, run):
    client, sec, pid, env, ids = ctx(name)
    sid = ids["backup"]
    start = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S")
    P.set_instance(sid, env, {"cronSchedule": "*/5 * * * *"})
    dep = P.deploy(sid, env)
    P.wait_status(dep, ("SUCCESS",))
    inst = gql("query($s:String!,$e:String!){serviceInstance(serviceId:$s,environmentId:$e){cronSchedule nextCronRunAt}}", {"s": sid, "e": env})["serviceInstance"]
    print("next", inst["nextCronRunAt"], flush=True)
    result = wait_end(dep, seconds=480, after=start)
    lines = [l for l in P.logs(dep, 500)]
    status = P.deployment(dep)["status"]  # read before the redeploy below replaces this deployment
    P.set_instance(sid, env, {"cronSchedule": P.BACKUP_CRON})
    restored = P.deploy(sid, env)
    P.wait_status(restored, ("SUCCESS",))
    data = {"schedule_during_test": "*/5 * * * *", "reference_schedule": P.BACKUP_CRON, "scheduled_for": inst["nextCronRunAt"],
            "container_started": next((l["timestamp"] for l in lines if "Starting Container" in l["message"]), None),
            "deployment_status": status, "result": result}
    if result.get("ok"):
        acct = account_id()
        base = P.sink_url(acct)
        s, body = sink_call(f"{base}/{result['key']}", sec["sink_read"])
        data["stored"] = {"http": s, "sha256_match": hashlib.sha256(body).hexdigest() == result["sha256"],
                          "starts_with_age_header": body.startswith(b"age-encryption.org/v1"), "contains_plain_marker": client["marker"].encode() in body}
        data["write_token_cannot_read"] = sink_call(f"{base}/{result['key']}", sec["sink_write"])[0]
        data["write_token_cannot_replace"] = sink_call(f"{base}/{result['key']}", sec["sink_write"], "PUT")[0]
    store(out_path(run, name, "cron.json"), data, run)
    print(json.dumps(data)[:700])
    stored = data.get("stored") or {}
    return (bool(result.get("ok")) and status == "SUCCESS" and stored.get("http") == 200 and stored.get("sha256_match") is True
            and stored.get("starts_with_age_header") is True and stored.get("contains_plain_marker") is False
            and data.get("write_token_cannot_read") == 403 and data.get("write_token_cannot_replace") == 409)


def backup_key(name, run, key=None):
    """The backup to restore: the one this run's scheduled job stored, or one named on the command line."""
    if key:
        return key
    path = out_path(run, name, "cron.json")
    if not os.path.exists(path):
        sys.exit(f"no {path}: run `prove.py cron {name}` for this run first, or pass --key")
    cron = json.load(open(path))
    if not cron.get("result", {}).get("ok") or not cron["result"].get("key"):
        sys.exit("the backup run of this run did not succeed: nothing to restore")
    return cron["result"]["key"]


def cmd_restore(name, run, key=None):
    client, sec, *_ = ctx(name)
    key = backup_key(name, run, key)
    lock = {k: v["ref"] for k, v in P.load_json("reference/versions.lock.json").items()}
    acct = account_id()
    base_run = P.Run(client, run)
    dest = f"{client['id']}-restore-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    pid, env = P.create_project(dest, base_run)  # refuses an existing name, so it only ever deletes what it created
    services_before = sorted(P.service_ids(pid))
    sec_restore = {"NOCODB_URL": "http://nocodb.railway.internal:8080"}
    pg = {"PGHOST": "postgres.railway.internal", "PGPORT": "5432"}
    admin = f"admin@{client['id']}.example"
    roles = {"LOADER_PASSWORD": sec["loader"], "NC_META_PASSWORD": sec["nc_meta"], "NC_READER_PASSWORD": sec["nc_reader"], "BACKUP_PASSWORD": sec["backup"]}
    spec = {
        "postgres": (lock["postgres"], {"POSTGRES_USER": "owner", "POSTGRES_PASSWORD": sec["postgres"], "POSTGRES_DB": "postgres", "PGDATA": "/var/lib/postgresql/data/pgdata"}, {}),
        "restore": (lock["ops"], {**pg, **roles, "OPS_JOB": "restore", "SOURCE_CLIENT": client["id"], "RESTORE_KEY": key, "POSTGRES_PASSWORD": sec["postgres"],
                                  "BACKUP_SINK_URL": P.sink_url(acct), "BACKUP_SINK_READ_TOKEN": sec["sink_read"], "BACKUP_AGE_IDENTITY": sec["age_identity"]}, {"restartPolicyType": "NEVER"}),
        "nocodb": (lock["nocodb"], {"NC_DB": f"pg://postgres.railway.internal:5432?u=nocodb_meta_owner&p={sec['nc_meta']}&d=nocodb_meta",
                                    "NC_ALLOW_LOCAL_EXTERNAL_DBS": "true", "NC_CONNECTION_ENCRYPT_KEY": sec["nc_enc"], "NC_AUTH_JWT_SECRET": sec["nc_jwt"],
                                    "NC_SITE_URL": "https://" + client["hostname"], "NC_INVITE_ONLY_SIGNUP": "true", "NC_DISABLE_TELE": "true",
                                    "NC_ADMIN_EMAIL": admin, "NC_ADMIN_PASSWORD": sec["nc_admin"], "PORT": "8080"}, {}),
        "verify": (lock["ops"], {**pg, "OPS_JOB": "restore-verify", "CLIENT_MARKER": client["marker"], "NOCODB_URL": sec_restore["NOCODB_URL"],
                                 "NC_ADMIN_EMAIL": admin, "NC_ADMIN_PASSWORD": sec["nc_admin"]}, {"restartPolicyType": "NEVER"}),
    }
    ids = {}
    for svc, (image, variables, settings) in spec.items():
        ids[svc] = gql("mutation($i:ServiceCreateInput!){serviceCreate(input:$i){id}}", {"i": {"projectId": pid, "environmentId": env, "name": svc}})["serviceCreate"]["id"]
        if svc == "postgres":
            P.ensure_volume(pid, env, ids, base_run)
        P.set_vars(pid, env, ids[svc], variables)
        P.set_instance(ids[svc], env, {"source": {"image": image}, "sleepApplication": False, **settings})
    P.wait_status(P.deploy(ids["postgres"], env), ("SUCCESS",))
    restored = wait_end(P.deploy(ids["restore"], env))
    verified = {}
    if restored.get("ok"):
        P.wait_status(P.deploy(ids["nocodb"], env), ("SUCCESS",))
        verified = wait_end(P.deploy(ids["verify"], env))
    empty_before = services_before == [] and restored.get("destination_databases_before") == [] and restored.get("destination_roles_before") == []
    ok = bool(restored.get("ok")) and bool(verified.get("ok")) and empty_before and restored.get("key") == key
    data = {"destination": dest, "destination_project_id": pid, "destination_services_before": services_before,
            "destination_empty_before": empty_before, "requested_key": key, "restore": restored, "verify": verified,
            "image_nocodb": lock["nocodb"], "image_postgres": lock["postgres"], "ok": ok}
    store(out_path(run, name, "restore.json"), data, run)
    print(json.dumps(data)[:800])
    if not ok:
        print(f"restore not verified: project {dest} kept for inspection", flush=True)
        return False
    gql("mutation($i:String!){projectDelete(id:$i)}", {"i": pid})  # the id created above, never one found by name
    base_run.note("project_deleted", id=pid, name=dest)
    return True


def cmd_memory(name, run):
    client, sec, pid, env, ids = ctx(name)
    start = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    data = {}
    for svc in ("postgres", "nocodb", "cloudflared"):
        series = gql("""query($s:String!,$e:String!,$st:DateTime!){metrics(serviceId:$s,environmentId:$e,startDate:$st,measurements:[MEMORY_USAGE_GB],sampleRateSeconds:30,averagingWindowSeconds:30){values{ts value}}}""",
                     {"s": ids[svc], "e": env, "st": start})["metrics"][0]["values"]
        nz = [v["value"] for v in series if v["value"] > 0]
        data[svc] = {"peak_gb": round(max(nz), 3) if nz else None, "last_gb": round(nz[-1], 3) if nz else None}
    store(out_path(run, name, "memory.json"), data, run)
    print(json.dumps(data))
    return all(v["peak_gb"] is not None for v in data.values())


def cmd_stop(name, run):
    client, sec, pid, env, ids = ctx(name)
    for svc in ("cloudflared", "nocodb", "backup", "postgres"):
        edges = gql("query($p:String!,$e:String!,$s:String!){deployments(first:1,input:{projectId:$p,environmentId:$e,serviceId:$s}){edges{node{id deploymentStopped}}}}",
                    {"p": pid, "e": env, "s": ids[svc]})["deployments"]["edges"]
        if edges and not edges[0]["node"]["deploymentStopped"]:
            gql("mutation($i:String!){deploymentStop(id:$i)}", {"i": edges[0]["node"]["id"]})
    print("stopped", name)
    return True


def cmd_start(name, run):
    client, sec, pid, env, ids = ctx(name)
    P.wait_status(P.deploy(ids["postgres"], env), ("SUCCESS",))
    P.wait_status(P.deploy(ids["nocodb"], env), ("SUCCESS",))
    P.wait_status(P.deploy(ids["cloudflared"], env), ("SUCCESS",))
    P.wait_status(P.deploy(ids["backup"], env), ("SUCCESS",))
    print("started", name)
    return True


def service_view(pid, env, ids):
    view = {}
    for name, sid in sorted(ids.items()):
        inst = gql("""query($s:String!,$e:String!){serviceInstance(serviceId:$s,environmentId:$e){source{image} startCommand cronSchedule sleepApplication restartPolicyType}}""", {"s": sid, "e": env})["serviceInstance"]
        variables = gql("query($p:String!,$e:String!,$s:String!){variables(projectId:$p,environmentId:$e,serviceId:$s)}", {"p": pid, "e": env, "s": sid})["variables"]
        domains = gql("""query($p:String!,$e:String!,$s:String!){domains(projectId:$p,environmentId:$e,serviceId:$s){serviceDomains{domain} customDomains{domain}}}""", {"p": pid, "e": env, "s": sid})["domains"]
        proxies = gql("query($s:String!,$e:String!){tcpProxies(serviceId:$s,environmentId:$e){domain}}", {"s": sid, "e": env})["tcpProxies"]
        view[name] = {"instance": inst, "variables": variables, "domains": len(domains["serviceDomains"]) + len(domains["customDomains"]), "tcp_proxies": len(proxies)}
    return view


def normalize(view, client, other_tokens):
    out = {}
    for svc, data in view.items():
        variables = {}
        for key, value in data["variables"].items():
            if key.startswith("RAILWAY_") or key in ("PEER_PRIVATE_HOST", "PEER_ADDRS"):
                continue
            if key in SECRET_VARS or key in ("BACKUP_AGE_RECIPIENT",):
                variables[key] = "<secret>"
            else:
                variables[key] = value.replace(client["id"], "<client>").replace(client["hostname"], "<hostname>").replace(client["marker"], "<marker>")
        out[svc] = {"instance": data["instance"], "variables": variables}
    return out


def cmd_audit(run):
    views, clients = {}, {}
    fingerprints, salt = {}, run
    for name in CLIENTS:
        client, sec, pid, env, ids = ctx(name)
        clients[name] = client
        views[name] = service_view(pid, env, ids)
        for svc, data in views[name].items():
            for key, value in data["variables"].items():
                if key in SECRET_VARS:
                    fingerprints.setdefault(name, {})[key] = hashlib.sha256((salt + value).encode()).hexdigest()[:12]
    a, b = fingerprints["acme-mech"], fingerprints["beacon-hvac"]
    shared = sorted(k for k in a if a[k] == b.get(k))
    all_values = list(a.values()) + list(b.values())
    inventory = {n: {s: {"domains": d["domains"], "tcp_proxies": d["tcp_proxies"]} for s, d in v.items()} for n, v in views.items()}
    exposed = [f"{n}/{s}" for n, v in inventory.items() for s, d in v.items() if d["domains"] or d["tcp_proxies"]]
    na, nb = normalize(views["acme-mech"], clients["acme-mech"], ()), normalize(views["beacon-hvac"], clients["beacon-hvac"], ())
    diffs = []
    for svc in sorted(set(na) | set(nb)):
        for section in ("instance", "variables"):
            left, right = na.get(svc, {}).get(section, {}), nb.get(svc, {}).get(section, {})
            for key in sorted(set(left) | set(right)):
                if left.get(key) != right.get(key):
                    diffs.append({"service": svc, "field": key, "a": left.get(key), "b": right.get(key)})
    images = {n: {s: d["instance"]["source"]["image"] for s, d in v.items()} for n, v in views.items()}
    runtime, deployed = {}, {}
    for name in CLIENTS:
        _, sec, pid, env, ids = ctx(name)
        dep = gql("query($p:String!,$e:String!,$s:String!){deployments(first:1,input:{projectId:$p,environmentId:$e,serviceId:$s}){edges{node{id}}}}",
                  {"p": pid, "e": env, "s": ids["cloudflared"]})["deployments"]["edges"][0]["node"]["id"]
        deployed[name] = {}
        for svc, sid in ids.items():
            edges = gql("query($p:String!,$e:String!,$s:String!){deployments(first:1,input:{projectId:$p,environmentId:$e,serviceId:$s}){edges{node{meta}}}}",
                        {"p": pid, "e": env, "s": sid})["deployments"]["edges"]
            deployed[name][svc] = (edges[0]["node"].get("meta") or {}).get("imageDigest") if edges else None
        found = [m.group(1) for m in (re.search(r"[Vv]ersion[ =]([0-9]{4}\.[0-9.]+)", l) for l in log_lines(dep)) if m]
        runtime[name] = found[0] if found else None
    lock = {k: v["ref"] for k, v in P.load_json("reference/versions.lock.json").items()}
    data = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "inventory": inventory, "exposed": exposed,
        "fingerprints": fingerprints, "shared_between_clients": shared, "distinct_values": len(set(all_values)), "total_values": len(all_values),
        "manifest": images, "manifest_identical": images["acme-mech"] == images["beacon-hvac"],
        "manifest_matches_lock": all(img in lock.values() for v in images.values() for img in v.values()),
        "config_diff": diffs, "lock": lock, "cloudflared_runtime": runtime, "deployed_digests": deployed,
        "deployed_identical": deployed["acme-mech"] == deployed["beacon-hvac"],
        "deployed_match_lock": all(d and any(d in ref for ref in lock.values()) for v in deployed.values() for d in v.values()),
    }
    store(out_path(run, "audit.json"), data, run)
    print(json.dumps({k: data[k] for k in ("exposed", "shared_between_clients", "distinct_values", "total_values", "manifest_identical", "manifest_matches_lock", "config_diff")})[:900])
    return (not exposed and not shared and data["distinct_values"] == data["total_values"] and data["manifest_identical"]
            and data["manifest_matches_lock"] and not diffs and data["deployed_identical"] and data["deployed_match_lock"])


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("command")
    ap.add_argument("client", nargs="?")
    ap.add_argument("--run", default=P.default_run())
    ap.add_argument("--key", help="restore: the backup key to restore instead of the one in this run's cron.json")
    args = ap.parse_args(argv)
    funcs = {"checks": cmd_checks, "outside": cmd_outside, "outside-cross": cmd_outside_cross, "replay": cmd_replay, "cron": cmd_cron,
             "restore": lambda c, r: cmd_restore(c, r, args.key), "memory": cmd_memory, "stop": cmd_stop, "start": cmd_start}
    ok = cmd_audit(args.run) if args.command == "audit" else funcs[args.command](args.client, args.run)
    if args.command not in ("outside", "outside-cross"):  # the Access checks never call Railway
        print("usage", round(usage(P.WS)["currentUsage"], 5))
    if not ok:
        print(f"FAILED: {args.command} {args.client or ''} (run {args.run})", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
