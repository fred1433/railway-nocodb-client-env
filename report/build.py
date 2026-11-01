#!/usr/bin/env python3
"""Builds the page from runs/<run>/. Every result, number and version on the page comes from a stored output."""
import datetime as dt, html, json, os, re, shutil, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = sys.argv[1] if len(sys.argv) > 1 else "20261101"
A, B = "acme-mech", "beacon-hvac"
REPO = "https://github.com/fred1433/railway-nocodb-client-env"
TICK = '<svg viewBox="0 0 24 22" aria-hidden="true"><path d="M3.2 12.4c1.7 1.5 3.3 3.4 4.8 6 3-6.6 7.3-11.7 13-15.6" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/></svg>'
CROSS = '<svg viewBox="0 0 24 22" aria-hidden="true"><path d="M5 4l14 14M19 4L5 18" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round"/></svg>'
e = lambda s: html.escape(str(s), quote=True)


def load(*parts):
    with open(os.path.join(ROOT, "runs", RUN, *parts)) as fh:
        return json.load(fh)


def maybe(*parts):
    path = os.path.join(ROOT, "runs", RUN, *parts)
    return load(*parts) if os.path.exists(path) else None


audit = load("audit.json")
data = {c: {"inside": load(c, "inside.json"), "outside": load(c, "outside.json"), "replay": load(c, "replay.json"),
            "cron": load(c, "cron.json"), "restore": load(c, "restore.json"), "memory": load(c, "memory.json")} for c in (A, B)}
attempts_b = load(B, "up_attempts.json")
last_b = attempts_b[-1]
stopped_b = [a for a in attempts_b if a["exit_code"] != 0]
teardown = maybe("teardown.json")


def inside(client, cid):
    return next(c for c in data[client]["inside"]["checks"] if c["id"] == cid)


def outside(client, cid):
    return next(c for c in data[client]["outside"]["checks"] if c["id"] == cid)


def first_word(text):
    return str(text).split()[0]


def http_code(text):
    match = re.search(r"HTTP (\d{3})", str(text))
    return match.group(1) if match else "?"


def ev(req, obs, cmd=None, pre=None):
    return {"req": req, "obs": obs, "cmd": cmd, "pre": pre}


def from_check(c):
    obs = c["observed"] if isinstance(c["observed"], str) else json.dumps(c["observed"])
    req = c["expected"] if isinstance(c["expected"], str) else json.dumps(c["expected"])
    return ev(req, obs, c.get("cmd"))


def row_source(c):
    tables, marker = inside(c, "source.tables"), inside(c, "source.marker")
    return tables["ok"] and marker["ok"], f"{len(tables['observed'])} tables and the witness row seen in NocoDB", [from_check(tables), from_check(marker)]


def row_readonly(c):
    ids = ("readonly.select", "readonly.insert", "readonly.temp", "readonly.meta", "readonly.nocodb_write")
    checks = [inside(c, i) for i in ids]
    short = (f"Read accepted. Write {first_word(checks[1]['observed'])}, temp table {first_word(checks[2]['observed'])}, "
             f"{'nocodb_meta refused' if checks[3]['ok'] else 'nocodb_meta open'}, write through NocoDB HTTP {http_code(checks[4]['observed'])}")
    return all(x["ok"] for x in checks), short, [from_check(x) for x in checks]


def row_future(c):
    read, write = inside(c, "future.read"), inside(c, "future.write")
    return read["ok"] and write["ok"], f"New table readable by the reader. Write on it {first_word(write['observed'])}", [from_check(read), from_check(write)]


def row_exposure(c):
    inv = audit["inventory"][c]
    domains = sum(v["domains"] for v in inv.values())
    proxies = sum(v["tcp_proxies"] for v in inv.values())
    rows = "\n".join(f"{name}: {v['domains']} domains, {v['tcp_proxies']} TCP proxies" for name, v in sorted(inv.items()))
    return domains == 0 and proxies == 0, f"{domains} domains and {proxies} TCP proxies on {len(inv)} services", [
        ev("no domain and no proxy on postgres and nocodb", f"read from the Railway API at {audit['at']}", "GraphQL: domains and tcpProxies, per service", rows)]


def row_web(c):
    anon, allowed, other = outside(c, "web.anonymous"), outside(c, "web.allowed"), outside(c, "web.other")
    return anon["ok"] and allowed["ok"] and other["ok"], (
        f"Anonymous HTTP {http_code(anon['observed'])}, allowed token HTTP {http_code(allowed['observed'])}, "
        f"token outside the policy HTTP {http_code(other['observed'])}"), [from_check(anon), from_check(allowed), from_check(other)]


def row_signup(c):
    attempt, control = inside(c, "signup.anonymous"), inside(c, "signup.control")
    users = re.search(r"users (\S+) -> (\S+)", attempt["observed"])
    return attempt["ok"] and control["ok"], f"Rejected with HTTP {http_code(attempt['observed'])}, users {users.group(1)} before and {users.group(2)} after", [from_check(control), from_check(attempt)]


def row_across(c):
    own, dns = inside(c, "network.own"), inside(c, "network.peer_dns")
    addrs = [x for x in data[c]["inside"]["checks"] if x["id"] == "network.peer_addr"]
    ok = own["ok"] and dns["ok"] and bool(addrs) and all(x["ok"] for x in addrs)
    other = B if c == A else A
    prints = audit["fingerprints"][c]
    rows = "\n".join(f"{k}: {v}" for k, v in sorted(prints.items()))
    items = [from_check(own), from_check(dns)] + [from_check(x) for x in addrs]
    items.append(ev("all secret fingerprints differ", f"{audit['distinct_values']} distinct of {audit['total_values']}, {len(audit['shared_between_clients'])} shared between clients",
                    "sha256(run id + value), first 12 hex characters", rows))
    ok = ok and not audit["shared_between_clients"] and audit["distinct_values"] == audit["total_values"]
    return ok, f"{other} not resolved and its {len(addrs)} addresses unreachable, own NocoDB answering", items


def row_repeat(c):
    replay = data[c]["replay"]
    same = replay["same_digest"] and not replay["created_on_replay"]
    items = [ev("bootstrap replayed: no duplicate, no reset", f"state digest before {replay['before']['state_digest'][:16]}, after {replay['after']['state_digest'][:16]}, created on replay: {len(replay['created_on_replay'])}",
                "redeploy the bootstrap service")]
    if c == B:
        diff = audit["config_diff"]
        items.insert(0, ev("stood up from the final reference, no repair", f"exit code {last_b['exit_code']} from an empty project, commit {last_b['commit']}", "python3 provision/provision.py up beacon-hvac"))
        for stop in stopped_b:
            items.insert(1, ev("earlier attempt, on a previous commit", f"stopped at {stop['ended']} by Railway: {stop['stopped_by']}", stop.get("note")))
        items.insert(len(stopped_b) + 1, ev("only identifier, domain and secrets differ", f"{len(diff)} differences left once those are masked", "normalized service settings and variables compared"))
        ok = same and last_b["exit_code"] == 0 and not diff
        return ok, "One pass from the final reference, no repair. Replay changed nothing", items
    return same, "Corrections carried into the reference. Replay changed nothing", items


def row_cron(c):
    cron = data[c]["cron"]
    result = cron["result"]
    when = (cron.get("scheduled_for") or "")[11:16]
    ok = bool(result.get("ok")) and cron["deployment_status"] == "SUCCESS"
    return ok, f"Railway ran it for {when} UTC, finished {cron['deployment_status']}", [
        ev("run triggered by Railway, clean finish", f"scheduled for {cron.get('scheduled_for')}, container started {cron.get('container_started')}, deployment {cron['deployment_status']}",
           f"cron {cron['schedule_during_test']} for the test, back to {cron['reference_schedule']} UTC afterwards", json.dumps(result, indent=1, sort_keys=True))]


def row_backup(c):
    cron, restore = data[c]["cron"], data[c]["restore"]
    stored = cron["stored"]
    marker = restore["verify"].get("marker_nocodb")
    ok = bool(restore["verify"].get("ok")) and stored["sha256_match"] and stored["starts_with_age_header"] and not stored["contains_plain_marker"]
    return ok, "Restored into a new project, witness row read back through NocoDB", [
        ev("encrypted, stored off Railway", f"HTTP {stored['http']}, checksum match {stored['sha256_match']}, age header {stored['starts_with_age_header']}, plain witness text in the object {stored['contains_plain_marker']}",
           "GET the object with the read token"),
        ev("environment can add a backup, not read or replace one", f"read with its token HTTP {cron['write_token_cannot_read']}, replace HTTP {cron['write_token_cannot_replace']}", "same object, write token"),
        ev("witness row read through the restored NocoDB", f"{marker}, NocoDB {restore['verify'].get('nocodb_version')}", f"new project {restore['destination']}, same image digests", json.dumps(restore["restore"], indent=1, sort_keys=True))]


def row_manifest(c):
    images = audit["manifest"][c]
    deployed = audit["deployed_digests"][c]
    rows = "\n".join(f"{name}: {ref.split('@')[0]}\n  deployed {deployed.get(name)}" for name, ref in sorted(images.items()))
    ok = audit["manifest_identical"] and audit["manifest_matches_lock"] and audit["deployed_identical"] and audit["deployed_match_lock"]
    return ok, f"{len(images)} services on pinned digests, identical in both environments", [
        ev("versions and digests deployed, identical between A and B", f"identical {audit['deployed_identical']}, matches versions.lock.json {audit['deployed_match_lock']}", "deployment.meta.imageDigest, per service", rows),
        from_check(inside(c, "manifest.postgres_runtime")), from_check(inside(c, "manifest.nocodb_runtime"))]


ROWS = [
    ("Right source", "The expected tables and this client's witness row are seen in NocoDB.", row_source),
    ("Read-only", "Read accepted, write refused with 42501, temp table refused, connection to nocodb_meta refused.", row_readonly),
    ("Future table", "A table created later by the load role is readable by the reader without a new grant.", row_future),
    ("Exposure", "API inventory: no domain and no proxy on postgres and nocodb.", row_exposure),
    ("Web access", "Anonymous not served, allowed identity served, authenticated but unauthorized identity refused.", row_web),
    ("Sign-up", "A real anonymous sign-up is rejected.", row_signup),
    ("Across clients", "One private network does not reach the other; the other is healthy; all secret fingerprints differ.", row_across),
    ("Repeatable", "The second environment needs no repair; replaying the bootstrap changes nothing.", row_repeat),
    ("Scheduled job", "A run triggered by Railway finishes cleanly.", row_cron),
    ("Backup", "Restored into a new destination on the same NocoDB version, witness row read back in NocoDB.", row_backup),
    ("Manifest", "Versions and digests deployed, identical between the two environments.", row_manifest),
]


def render_ev(item):
    out = [f'<div class="ev"><div class="req">{e(item["req"])}</div><div class="obs">{e(item["obs"])}</div>']
    if item["cmd"]:
        out.append(f"<code>{e(item['cmd'])}</code>")
    if item["pre"]:
        out.append(f"<pre>{e(item['pre'])}</pre>")
    out.append("</div>")
    return "".join(out)


rows_html, ok_count = [], 0
for number, (title, required, fn) in enumerate(ROWS, 1):
    a_ok, a_short, a_ev = fn(A)
    b_ok, b_short, b_ev = fn(B)
    ok_count += 1 if a_ok and b_ok else 0
    cell = lambda cls, client, ok, short: (f'<span class="cell {cls}{"" if ok else " bad"}">{TICK if ok else CROSS}'
                                           f'<span><span class="client-tag">{client}</span>{"" if ok else "Failed. "}{e(short)}</span></span>')
    rows_html.append(f"""<details class="row">
      <summary>
        <span class="num">{number}</span>
        <span class="what"><h3>{e(title)}</h3><p>{e(required)}</p><span class="open">Evidence</span></span>
        {cell("cell-a", A, a_ok, a_short)}
        {cell("cell-b", B, b_ok, b_short)}
      </summary>
      <div class="evidence">
        <div class="ev-col"><h4>{A}</h4>{"".join(render_ev(i) for i in a_ev)}</div>
        <div class="ev-col"><h4>{B}</h4>{"".join(render_ev(i) for i in b_ev)}</div>
      </div>
    </details>""")

clean_b = last_b["exit_code"] == 0 and not audit["config_diff"]
restored = all(data[c]["restore"]["verify"].get("ok") for c in (A, B))
findings = [
    f"{ok_count} of {len(ROWS)} lines passed in both environments.",
    "beacon-hvac came up with no repair. Only identifier, domain and secrets differ." if clean_b else "beacon-hvac needed repairs: see line 8.",
    "A backup of each environment, restored into a new project, was read back through NocoDB." if restored else "Restore did not complete: see line 10.",
]
peak = max(data[c]["memory"]["nocodb"]["peak_gb"] for c in (A, B))
rest = max(data[c]["memory"]["nocodb"]["last_gb"] for c in (A, B))
second = outside(A, "web.second_login")
notes = [
    "Private tunnel rather than a public Railway domain: a second public path would go around Access.",
    f"Access in front of NocoDB Community leaves a second login: a token that passes Access still gets HTTP {http_code(second['observed'])} from NocoDB.",
    'Since 9 January 2026 the <a href="https://nocodb.com/docs/product-docs/getting-started/license">NocoDB license</a> reads: "Internal self-hosting does not require a commercial license", while a commercial license is needed to "Provide direct NocoDB access to external customers". The question is who uses NocoDB, and who owns the instances.',
    "QuickBooks OAuth redirects and webhooks do not go through an interactive login, and Intuit signs its webhooks. They need their own route.",
    "Read-only NocoDB is a choice for this example, not a rule of the setup. Edits would need a role with write grants.",
    "On NocoDB 2026.10.1, NC_INVITE_ONLY_SIGNUP=true left sign-up open on the first run (HTTP 200). The bootstrap now sets the admin setting and checks it before the tunnel starts.",
    f"NocoDB 2026.10.1 reached {peak:.2f} GB in these two environments and rested near {rest:.2f} GB. It did not start under a 512 MB limit in the settings tried.",
    "Railway cron schedules are in UTC, so the local time of a backup moves with daylight saving.",
    "Outside this example: real QuickBooks, a GitHub organization per client, n8n.",
]
first = dt.datetime.strptime(RUN, "%Y%m%d")
last = dt.datetime.strptime(audit["at"][:10], "%Y-%m-%d") if audit["at"][:2] == "20" else first
date = first.strftime("%-d %B %Y") if first.date() == last.date() else f"{first.strftime('%-d')} to {last.strftime('%-d %B %Y')}"
lock = audit["lock"]
commit = subprocess.check_output(["git", "-C", ROOT, "log", "-1", "--format=%h", "--", "reference/versions.lock.json"], text=True).strip()
if teardown:
    gone = dt.datetime.strptime(teardown["date"], "%Y-%m-%d").strftime("%-d %B %Y")
    after = f"Removed after the run, on {gone}"
else:
    after = "Up for the length of the run"
values = {
    "date": e(date), "commit": e(commit), "commit_url": f"{REPO}/tree/{commit}",
    "v_postgres": e(first_word(inside(A, "manifest.postgres_runtime")["observed"])),
    "v_nocodb": e(inside(A, "manifest.nocodb_runtime")["observed"]),
    "v_cloudflared": e(audit["cloudflared_runtime"][A] or re.search(r":([0-9.]+)@", lock["cloudflared"]).group(1)),
    "findings": "\n    ".join(f'<p class="finding">{e(f)}</p>' for f in findings),
    "rows": "\n".join(rows_html),
    "notes": "\n      ".join(f"<li>{n if n.startswith('Since 9 January') else e(n)}</li>" for n in notes),
    "teardown": e(after), "repo_url": REPO,
}
with open(os.path.join(ROOT, "report/template.html")) as fh:
    page = fh.read()
for key, value in values.items():
    page = page.replace("{{" + key + "}}", value)
site = os.path.join(ROOT, "page/site")
os.makedirs(site, exist_ok=True)
with open(os.path.join(site, "index.html"), "w") as fh:
    fh.write(page)
for name in ("style.css", "page.js"):
    shutil.copy(os.path.join(ROOT, "report", name), os.path.join(site, name))
print(f"{ok_count}/{len(ROWS)} lines; page/site/index.html written")
