#!/usr/bin/env python3
"""Stand up one client environment from reference/, or remove it.

    python3 provision/provision.py up acme-mech --run 20261101
    python3 provision/provision.py redeploy acme-mech bootstrap --run 20261101
    python3 provision/provision.py down acme-mech

Needs RAILWAY_API_TOKEN, RAILWAY_WORKSPACE_ID and CLOUDFLARE_API_TOKEN. Generated secrets stay in
.secrets/<client>.json (git-ignored). Running `up` twice converges: nothing is regenerated.
"""
import argparse, json, os, secrets, subprocess, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from railway_api import gql, usage, RailwayError
from cloudflare_api import cf, account_id, zone_id

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WS = os.environ.get("RAILWAY_WORKSPACE_ID", "")
ZONE = "theaipipe.com"
USAGE_STOP = 3.8
SERVICES = ("postgres", "bootstrap", "nocodb", "cloudflared", "backup", "checks")
BACKUP_CRON = "17 8 * * *"  # UTC


def load_json(path):
    with open(os.path.join(ROOT, path)) as fh:
        return json.load(fh)


class Run:
    def __init__(self, client, run_id):
        self.dir = os.path.join(ROOT, "runs", run_id, client["id"])
        os.makedirs(self.dir, exist_ok=True)

    def note(self, step, **fields):
        rec = {"t": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "step": step, **fields}
        with open(os.path.join(self.dir, "provision.jsonl"), "a") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
        print(json.dumps(rec, sort_keys=True)[:260], flush=True)

    def guard(self):
        u = usage(WS)
        self.note("usage", current=round(u["currentUsage"], 5))
        if u["currentUsage"] >= USAGE_STOP:
            sys.exit(f"usage {u['currentUsage']:.2f} reached the stop line {USAGE_STOP}")


def load_secrets(client):
    path = os.path.join(ROOT, ".secrets", client["id"] + ".json")
    data = json.load(open(path)) if os.path.exists(path) else {}
    for key in ("postgres", "loader", "nc_meta", "nc_reader", "backup", "sink_write", "sink_read"):
        data.setdefault(key, secrets.token_hex(24))
    data.setdefault("nc_admin", "Ab1!" + secrets.token_hex(16))
    data.setdefault("nc_jwt", secrets.token_hex(32))
    data.setdefault("nc_enc", secrets.token_hex(32))
    if "age_identity" not in data:
        out = subprocess.run(["age-keygen"], capture_output=True, text=True, check=True)
        data["age_identity"] = next(l for l in out.stdout.splitlines() if l.startswith("AGE-SECRET-KEY-"))
        data["age_recipient"] = next(l.split(": ")[1] for l in out.stdout.splitlines() if "public key" in l)
    return data, path


def save_secrets(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(data, fh)
    os.chmod(path, 0o600)


# Cloudflare ---------------------------------------------------------------------------------------

def ensure_tunnel(acct, client, sec, run):
    found = cf("GET", f"accounts/{acct}/cfd_tunnel?name={client['access_name']}&is_deleted=false")
    tunnel = found[0] if found else cf("POST", f"accounts/{acct}/cfd_tunnel", {"name": client["access_name"], "config_src": "cloudflare"})
    sec["tunnel_id"] = tunnel["id"]
    sec["tunnel_token"] = cf("GET", f"accounts/{acct}/cfd_tunnel/{tunnel['id']}/token")
    run.note("tunnel", id=tunnel["id"], reused=bool(found))


def ensure_service_token(acct, name, sec, slot):
    if slot in sec:
        return
    tok = cf("POST", f"accounts/{acct}/access/service_tokens", {"name": name, "duration": "8760h"})
    sec[slot] = {"id": tok["id"], "client_id": tok["client_id"], "client_secret": tok["client_secret"]}


def ensure_access(acct, client, sec, run):
    name = client["access_name"]
    ensure_service_token(acct, name + "-allowed", sec, "svc_allowed")
    ensure_service_token(acct, name + "-other", sec, "svc_other")
    policies = cf("GET", f"accounts/{acct}/access/policies?per_page=100")
    policy = next((p for p in policies if p["name"] == name), None)
    if not policy:
        policy = cf("POST", f"accounts/{acct}/access/policies", {
            "name": name, "decision": "non_identity", "include": [{"service_token": {"token_id": sec["svc_allowed"]["id"]}}]})
    apps = cf("GET", f"accounts/{acct}/access/apps?per_page=100")
    app = next((a for a in apps if a["name"] == name), None)
    otp = next(i["id"] for i in cf("GET", f"accounts/{acct}/access/identity_providers") if i["type"] == "onetimepin")
    if not app:
        app = cf("POST", f"accounts/{acct}/access/apps", {
            "name": name, "domain": client["hostname"], "type": "self_hosted", "session_duration": "1h",
            "allowed_idps": [otp], "auto_redirect_to_identity": False, "app_launcher_visible": False,
            "policies": [{"id": policy["id"], "precedence": 1}]})
    sec["access_app_id"], sec["access_aud"], sec["access_policy_id"] = app["id"], app["aud"], policy["id"]
    run.note("access", app=name, policy=policy["id"], identity_provider="onetimepin")


def team_name(acct):
    return cf("GET", f"accounts/{acct}/access/organizations")["auth_domain"].split(".")[0]


def ensure_tunnel_route(acct, zone, client, sec, run):
    origin = f"http://nocodb-{client['id']}.railway.internal:8080"
    cf("PUT", f"accounts/{acct}/cfd_tunnel/{sec['tunnel_id']}/configurations", {"config": {"ingress": [
        {"hostname": client["hostname"], "service": origin,
         "originRequest": {"access": {"required": True, "teamName": team_name(acct), "audTag": [sec["access_aud"]]}}},
        {"service": "http_status:404"}]}})
    existing = cf("GET", f"zones/{zone}/dns_records?name={client['hostname']}")
    content = sec["tunnel_id"] + ".cfargotunnel.com"
    if not existing:
        cf("POST", f"zones/{zone}/dns_records", {"type": "CNAME", "name": client["hostname"], "content": content, "proxied": True})
    run.note("tunnel_route", hostname=client["hostname"], protect_with_access=True, dns_created=not existing)


def ensure_sink_secrets(acct, client, sec):
    suffix = client["id"].upper().replace("-", "_")
    for name, value in ((f"WRITE_{suffix}", sec["sink_write"]), (f"READ_{suffix}", sec["sink_read"])):
        cf("PUT", f"accounts/{acct}/workers/scripts/railway-check-backup-sink/secrets",
           {"name": name, "text": value, "type": "secret_text"})


def sink_url(acct):
    return f"https://railway-check-backup-sink.{cf('GET', f'accounts/{acct}/workers/subdomain')['subdomain']}.workers.dev"


# Railway ------------------------------------------------------------------------------------------

def ensure_project(client, run):
    projects = gql("query{projects{edges{node{id name environments{edges{node{id name}}}}}}}")["projects"]["edges"]
    node = next((e["node"] for e in projects if e["node"]["name"] == client["project"]), None)
    if not node:
        node = gql("mutation($i:ProjectCreateInput!){projectCreate(input:$i){id name environments{edges{node{id name}}}}}",
                   {"i": {"name": client["project"], "workspaceId": WS, "defaultEnvironmentName": "production"}})["projectCreate"]
        run.note("project_created", id=node["id"])
    return node["id"], node["environments"]["edges"][0]["node"]["id"]


def service_ids(pid):
    edges = gql("query($p:String!){project(id:$p){services{edges{node{id name}}}}}", {"p": pid})["project"]["services"]["edges"]
    return {e["node"]["name"]: e["node"]["id"] for e in edges}


def set_vars(pid, env, sid, variables):
    gql("mutation($i:VariableCollectionUpsertInput!){variableCollectionUpsert(input:$i)}",
        {"i": {"projectId": pid, "environmentId": env, "serviceId": sid, "variables": variables, "skipDeploys": True}})


def set_instance(sid, env, settings):
    gql("mutation($s:String!,$e:String!,$i:ServiceInstanceUpdateInput!){serviceInstanceUpdate(serviceId:$s,environmentId:$e,input:$i)}",
        {"s": sid, "e": env, "i": settings})


def deploy(sid, env):
    return gql("mutation($s:String!,$e:String!){serviceInstanceDeployV2(serviceId:$s,environmentId:$e)}", {"s": sid, "e": env})["serviceInstanceDeployV2"]


def deployment(dep_id):
    return gql("query($d:String!){deployment(id:$d){id status}}", {"d": dep_id})["deployment"]


def logs(dep_id, limit=800):
    return gql("query($d:String!,$l:Int!){deploymentLogs(deploymentId:$d,limit:$l){timestamp message}}", {"d": dep_id, "l": limit})["deploymentLogs"]


def wait_status(dep_id, want, seconds=240):
    deadline = time.time() + seconds
    status = None
    while time.time() < deadline:
        status = deployment(dep_id)["status"]
        if status in want:
            return status
        if status in ("FAILED", "CRASHED", "REMOVED"):
            sys.exit(f"deployment {dep_id[:8]} ended {status}")
        time.sleep(4)
    sys.exit(f"deployment {dep_id[:8]} still {status} after {seconds}s")


def wait_log(dep_id, tag, seconds=600):
    """Return the parsed payload of the first log line starting with tag; a failed JOB_RESULT stops the run."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        for line in logs(dep_id):
            msg = line["message"].strip()
            if msg.startswith("JOB_RESULT ") and json.loads(msg[11:]).get("ok") is False:
                sys.exit("job failed: " + msg[:400])
            if msg.startswith(tag + " "):
                return json.loads(msg[len(tag) + 1:])
        time.sleep(5)
    sys.exit(f"no {tag} line in deployment {dep_id[:8]} after {seconds}s")


def desired(client, sec, lock, sink):
    host = f"http://nocodb-{client['id']}.railway.internal:8080"
    admin = f"admin@{client['id']}.example"
    pg_common = {"PGHOST": "postgres.railway.internal", "PGPORT": "5432", "CLIENT_ID": client["id"]}
    return {
        "postgres": {"image": lock["postgres"], "settings": {"sleepApplication": False}, "variables": {
            "POSTGRES_USER": "owner", "POSTGRES_PASSWORD": sec["postgres"], "POSTGRES_DB": "postgres",
            "PGDATA": "/var/lib/postgresql/data/pgdata"}},
        "bootstrap": {"image": lock["ops"], "settings": {"sleepApplication": False, "restartPolicyType": "NEVER"}, "variables": {
            **pg_common, "OPS_JOB": "bootstrap", "CLIENT_MARKER": client["marker"], "POSTGRES_PASSWORD": sec["postgres"],
            "LOADER_PASSWORD": sec["loader"], "NC_META_PASSWORD": sec["nc_meta"], "NC_READER_PASSWORD": sec["nc_reader"],
            "BACKUP_PASSWORD": sec["backup"], "NOCODB_URL": host, "NC_ADMIN_EMAIL": admin, "NC_ADMIN_PASSWORD": sec["nc_admin"]}},
        "nocodb": {"image": lock["nocodb"], "settings": {"sleepApplication": False}, "variables": {
            "NC_DB": f"pg://postgres.railway.internal:5432?u=nocodb_meta_owner&p={sec['nc_meta']}&d=nocodb_meta",
            "NC_ALLOW_LOCAL_EXTERNAL_DBS": "true", "NC_CONNECTION_ENCRYPT_KEY": sec["nc_enc"], "NC_AUTH_JWT_SECRET": sec["nc_jwt"],
            "NC_SITE_URL": "https://" + client["hostname"], "NC_INVITE_ONLY_SIGNUP": "true", "NC_DISABLE_TELE": "true",
            "NC_ADMIN_EMAIL": admin, "NC_ADMIN_PASSWORD": sec["nc_admin"], "PORT": "8080"}},
        "cloudflared": {"image": lock["cloudflared"],
                        "settings": {"sleepApplication": False, "startCommand": "cloudflared tunnel --no-autoupdate run"},
                        "variables": {"TUNNEL_TOKEN": sec["tunnel_token"], "NO_AUTOUPDATE": "true"}},
        "backup": {"image": lock["ops"], "settings": {"sleepApplication": False, "restartPolicyType": "NEVER", "cronSchedule": BACKUP_CRON}, "variables": {
            **pg_common, "OPS_JOB": "backup", "BACKUP_PASSWORD": sec["backup"], "BACKUP_SINK_URL": sink,
            "BACKUP_SINK_TOKEN": sec["sink_write"], "BACKUP_AGE_RECIPIENT": sec["age_recipient"]}},
        "checks": {"image": lock["ops"], "settings": {"sleepApplication": False, "restartPolicyType": "NEVER"}, "variables": {
            **pg_common, "OPS_JOB": "checks", "CLIENT_MARKER": client["marker"], "LOADER_PASSWORD": sec["loader"],
            "NC_READER_PASSWORD": sec["nc_reader"], "NOCODB_URL": host, "NC_ADMIN_EMAIL": admin, "NC_ADMIN_PASSWORD": sec["nc_admin"],
            "OWN_PRIVATE_HOST": f"nocodb-{client['id']}.railway.internal"}},
    }


def ensure_services(pid, env, spec, run):
    ids = service_ids(pid)
    for name in SERVICES:
        if name not in ids:
            # Created without a source so that nothing deploys before its variables are set.
            ids[name] = gql("mutation($i:ServiceCreateInput!){serviceCreate(input:$i){id}}",
                            {"i": {"projectId": pid, "environmentId": env, "name": name}})["serviceCreate"]["id"]
            run.note("service_created", name=name)
        set_vars(pid, env, ids[name], spec[name]["variables"])
        set_instance(ids[name], env, {"source": {"image": spec[name]["image"]}, **spec[name]["settings"]})
    return ids


def ensure_volume(pid, env, ids, run):
    volumes = gql("query($p:String!){project(id:$p){volumes{edges{node{id}}}}}", {"p": pid})["project"]["volumes"]["edges"]
    if not volumes:
        gql("mutation($i:VolumeCreateInput!){volumeCreate(input:$i){id}}", {"i": {
            "projectId": pid, "environmentId": env, "serviceId": ids["postgres"], "mountPath": "/var/lib/postgresql/data"}})
        run.note("volume_created", service="postgres")


def ensure_private_name(env, ids, client, run):
    network = gql("query($e:String!){privateNetworks(environmentId:$e){publicId}}", {"e": env})["privateNetworks"][0]["publicId"]
    endpoint = gql("query($e:String!,$n:String!,$s:String!){privateNetworkEndpoint(environmentId:$e,privateNetworkId:$n,serviceId:$s){publicId dnsName}}",
                   {"e": env, "n": network, "s": ids["nocodb"]})["privateNetworkEndpoint"]
    want = f"nocodb-{client['id']}"
    if endpoint["dnsName"] != want:
        gql("mutation($d:String!,$i:String!,$n:String!){privateNetworkEndpointRename(dnsName:$d,id:$i,privateNetworkId:$n)}",
            {"d": want, "i": endpoint["publicId"], "n": network})
    run.note("private_name", dns=want + ".railway.internal")


def up(client, run):
    lock = {k: v["ref"] for k, v in load_json("reference/versions.lock.json").items()}
    sec, path = load_secrets(client)
    acct, zone = account_id(), zone_id(ZONE)
    run.note("start", client=client["id"], images=lock)
    ensure_tunnel(acct, client, sec, run)
    ensure_access(acct, client, sec, run)
    ensure_sink_secrets(acct, client, sec)
    save_secrets(sec, path)
    pid, env = ensure_project(client, run)
    sec["project_id"], sec["environment_id"] = pid, env
    save_secrets(sec, path)
    spec = desired(client, sec, lock, sink_url(acct))
    ids = ensure_services(pid, env, spec, run)
    ensure_volume(pid, env, ids, run)
    ensure_tunnel_route(acct, zone, client, sec, run)

    run.note("deploy", service="postgres")
    wait_status(deploy(ids["postgres"], env), ("SUCCESS",))
    run.note("deploy", service="bootstrap")
    boot = deploy(ids["bootstrap"], env)
    wait_log(boot, "DB_PHASE", 300)
    run.note("deploy", service="nocodb")
    wait_status(deploy(ids["nocodb"], env), ("SUCCESS",))
    ensure_private_name(env, ids, client, run)  # the endpoint only exists once the service has deployed
    result = wait_log(boot, "JOB_RESULT", 600)
    run.note("bootstrap_done", created=result["created"], state_digest=result["state_digest"], seconds=result["seconds"])
    run.note("deploy", service="cloudflared")
    wait_status(deploy(ids["cloudflared"], env), ("SUCCESS",))
    wait_status(deploy(ids["backup"], env), ("SUCCESS",))
    run.note("up_complete", client=client["id"])
    run.guard()


def redeploy(client, name, run):
    sec, _ = load_secrets(client)
    pid, env = sec["project_id"], sec["environment_id"]
    dep = deploy(service_ids(pid)[name], env)
    run.note("redeploy", service=name, deployment=dep)
    print(dep)


def down(client):
    sec, path = load_secrets(client)
    acct, zone = account_id(), zone_id(ZONE)
    removed = []
    if sec.get("project_id"):
        gql("mutation($i:String!){projectDelete(id:$i)}", {"i": sec["project_id"]})
        removed.append("railway project " + client["project"])
    for rec in cf("GET", f"zones/{zone}/dns_records?name={client['hostname']}"):
        cf("DELETE", f"zones/{zone}/dns_records/{rec['id']}")
        removed.append("dns " + client["hostname"])
    if sec.get("access_app_id"):
        cf("DELETE", f"accounts/{acct}/access/apps/{sec['access_app_id']}")
        removed.append("access app " + client["access_name"])
    if sec.get("access_policy_id"):
        cf("DELETE", f"accounts/{acct}/access/policies/{sec['access_policy_id']}")
        removed.append("access policy " + client["access_name"])
    for slot in ("svc_allowed", "svc_other"):
        if slot in sec:
            cf("DELETE", f"accounts/{acct}/access/service_tokens/{sec[slot]['id']}")
            removed.append("service token " + slot)
    if sec.get("tunnel_id"):
        cf("DELETE", f"accounts/{acct}/cfd_tunnel/{sec['tunnel_id']}/connections")
        cf("DELETE", f"accounts/{acct}/cfd_tunnel/{sec['tunnel_id']}")
        removed.append("tunnel " + client["access_name"])
    print(json.dumps(removed, indent=1))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=("up", "redeploy", "down"))
    ap.add_argument("client")
    ap.add_argument("service", nargs="?")
    ap.add_argument("--run", default=time.strftime("%Y%m%d", time.gmtime()))
    args = ap.parse_args()
    client = load_json(f"reference/clients/{args.client}.json")
    run = Run(client, args.run)
    {"up": lambda: up(client, run), "redeploy": lambda: redeploy(client, args.service, run), "down": lambda: down(client)}[args.command]()
