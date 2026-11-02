#!/usr/bin/env python3
"""Builds the page from runs/<run>/. Every result, number and version on the page comes from a stored output.

    python3 report/build.py 20261101      rebuild page/site/ from the archived run, nothing deployed

It refuses to build when a proof is missing, or when a proof does not belong to this run (another run id, a
restore of another backup than the one this run stored, a timestamp outside the run).
"""
import ast, datetime as dt, html, json, os, re, shutil, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = sys.argv[1] if len(sys.argv) > 1 else "20261101"
A, B = "acme-mech", "beacon-hvac"
REPO = "https://github.com/fred1433/railway-nocodb-client-env"
TICK = '<svg viewBox="0 0 24 22" aria-hidden="true"><path d="M3.2 12.4c1.7 1.5 3.3 3.4 4.8 6 3-6.6 7.3-11.7 13-15.6" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/></svg>'
CROSS = '<svg viewBox="0 0 24 22" aria-hidden="true"><path d="M5 4l14 14M19 4L5 18" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round"/></svg>'
e = lambda s: html.escape(str(s), quote=True)
PER_CLIENT = ("inside.json", "outside.json", "outside_cross.json", "replay.json", "cron.json", "restore.json", "memory.json")
SHARED = ("audit.json", "sink_concurrency.json", os.path.join(B, "up_attempts.json"))


def refuse(reason):
    sys.exit(f"refusing to build the report for run {RUN}: {reason}")


def path_of(*parts):
    return os.path.join(ROOT, "runs", RUN, *parts)


def load(*parts):
    with open(path_of(*parts)) as fh:
        return json.load(fh)


missing = [os.path.join(c, f) for c in (A, B) for f in PER_CLIENT if not os.path.exists(path_of(c, f))]
missing += [f for f in SHARED if not os.path.exists(path_of(f))]
if missing:
    refuse("missing " + ", ".join(sorted(missing)))
audit = load("audit.json")
data = {c: {f[:-5]: load(c, f) for f in PER_CLIENT} for c in (A, B)}
concurrency = load("sink_concurrency.json")
attempts_b = load(B, "up_attempts.json")
last_b = attempts_b[-1]
stopped_b = [a for a in attempts_b if a["exit_code"] != 0]
teardown = load("teardown.json") if os.path.exists(path_of("teardown.json")) else None
clients = {c: json.load(open(os.path.join(ROOT, "reference/clients", c + ".json"))) for c in (A, B)}


def check_membership():
    """A proof belongs to this run: same run id when it carries one, dates inside the run, and the restore read the
    backup that this run's scheduled job stored. Files written before run ids were recorded are checked by date and keys."""
    first = dt.datetime.strptime(RUN, "%Y%m%d").date()
    last = dt.date.fromisoformat(audit["at"][:10])
    stamps = [("audit.json", audit["at"]), ("sink_concurrency.json", concurrency["at"])]
    files = [("audit.json", audit), ("sink_concurrency.json", concurrency)]
    for c in (A, B):
        d = data[c]
        files += [(f"{c}/{name}.json", d[name]) for name in d]
        stamps += [(f"{c}/inside.json", d["inside"]["at"]), (f"{c}/outside.json", d["outside"]["at"]),
                   (f"{c}/outside_cross.json", d["outside_cross"]["at"]), (f"{c}/cron.json", d["cron"]["scheduled_for"])]
        if d["restore"]["restore"].get("key") != d["cron"]["result"].get("key"):
            refuse(f"{c}: restore.json restored {d['restore']['restore'].get('key')}, cron.json of this run stored {d['cron']['result'].get('key')}")
        if d["restore"]["verify"].get("ok") and d["restore"]["verify"].get("marker_nocodb") != clients[c]["marker"]:
            refuse(f"{c}: restore.json read another client's test record")
    for name, content in files:
        if isinstance(content, dict) and "run" in content and content["run"] != RUN:
            refuse(f"{name} belongs to run {content['run']}")
    for name, stamp in stamps:
        day = dt.date.fromisoformat(str(stamp)[:10])
        if not first <= day <= max(last, dt.date.fromisoformat(concurrency["at"][:10])):
            refuse(f"{name} is dated {stamp}, outside the run ({first} to {last})")


check_membership()


def inside(client, cid):
    return next(c for c in data[client]["inside"]["checks"] if c["id"] == cid)


def outside(client, cid, cross=False):
    return next((c for c in data[client]["outside_cross" if cross else "outside"]["checks"] if c["id"] == cid), None)


def first_word(text):
    return str(text).split()[0]


def http_code(text):
    match = re.search(r"HTTP (\d{3})", str(text))
    return match.group(1) if match else "?"


def first_sentence(text):
    text = " ".join(str(text).split())
    end = text.find(". ")
    return text if end < 0 else text[:end + 1]


def signup_parts(observed):
    """Status, NocoDB message cut at its first sentence, and user counts, from either output format."""
    status = http_code(observed)
    old = re.match(r"HTTP \d{3} (.*); users (\S+) -> (\S+)$", observed)
    new = re.match(r"HTTP \d{3} (.*) Users (\S+) before, (\S+) after\.$", observed)
    said, before, after = (old or new).groups()
    return status, first_sentence(said).rstrip(" .") + ".", before, after


def tidy(cid, observed):
    """Readable evidence: no Python reprs, no None/True/False, messages cut at a sentence."""
    if isinstance(observed, list):
        return ", ".join(map(str, observed))
    if isinstance(observed, dict) and "addrs" in observed:
        return f"resolves to {', '.join(observed['addrs'])}; port 8080 {observed['tcp_8080']}"
    text = str(observed)
    if cid == "future.read" and text in ("created after the grants", "inserted by the load role"):
        return "nocodb_reader read the row that client_loader inserted after the grants"
    if cid == "signup.anonymous":
        status, said, before, after = signup_parts(text)
        return f"HTTP {status} “{said}” Users {before} before, {after} after."
    with_body = re.match(r"(HTTP \d{3}) (\{.*)$", text)
    if with_body:
        status, raw = with_body.groups()
        body = None
        for parse in (json.loads, ast.literal_eval):
            try:
                body = parse(raw)
                break
            except (ValueError, SyntaxError):
                pass
        if isinstance(body, dict) and "uptime" in body:
            return f"{status}, NocoDB health {body.get('message')}, up {round(body['uptime'])} s"
        if isinstance(body, dict):
            return f"{status} {body.get('error', '')}: {body.get('message', '')}".strip()
        error = re.search(r'"error":"(\w+)"', raw)
        if error:
            return f"{status} {error.group(1)}"
    text = re.sub(r", Location host None$", ", no redirect", text)
    text = re.sub(r", Location host (\S+)$", r", redirected to \1", text)
    text = re.sub(r"\b[A-Z]\w*Error: ", "", text)
    text = re.sub(r"\[Errno -?\d+\] ", "", text)
    if cid == "network.peer_dns":
        text = "not resolved (" + text[:1].lower() + text[1:] + ")"
    elif cid == "network.peer_addr":
        text = re.sub(r": (\w)", lambda m: ": " + m.group(1).lower(), text, count=1)
    return text


def ev(req, obs, cmd=None, pre=None):
    return {"req": req, "obs": obs, "cmd": cmd, "pre": pre}


def from_check(c, req=None):
    expected = c["expected"] if isinstance(c["expected"], str) else ", ".join(map(str, c["expected"]))
    return ev(req or expected, tidy(c["id"], c["observed"]), c.get("cmd"))


def yes(flag):
    return "yes" if flag else "no"


def row_source(c):
    tables, marker = inside(c, "source.tables"), inside(c, "source.marker")
    ok = tables["ok"] and marker["ok"]
    return ok, (f"{len(tables['observed'])} tables and the client-specific test record seen in NocoDB" if ok else
                "Expected tables or client-specific test record not seen in NocoDB"), [from_check(tables), from_check(marker, "client-specific test record")]


def row_readonly(c):
    ids = ("readonly.select", "readonly.insert", "readonly.temp", "readonly.meta", "readonly.nocodb_write")
    checks = [inside(c, i) for i in ids]
    short = (f"Read {'accepted' if checks[0]['ok'] else 'failed'}. Write {first_word(checks[1]['observed'])}, temp table {first_word(checks[2]['observed'])}, "
             f"{'nocodb_meta refused' if checks[3]['ok'] else 'nocodb_meta not refused'}, write through NocoDB HTTP {http_code(checks[4]['observed'])}")
    return all(x["ok"] for x in checks), short, [from_check(checks[0], "the client-specific test record is readable")] + [from_check(x) for x in checks[1:]]


def row_future(c):
    read, write = inside(c, "future.read"), inside(c, "future.write")
    ok = read["ok"] and write["ok"]
    return ok, (f"New table readable by the reader. Write on it {first_word(write['observed'])}" if ok else
                "New table not readable, or writable, by the reader"), [from_check(read), from_check(write)]


def row_exposure(c):
    inv = audit["inventory"][c]
    domains = sum(v["domains"] for v in inv.values())
    proxies = sum(v["tcp_proxies"] for v in inv.values())
    rows = "\n".join(f"{name}: {v['domains']} domains, {v['tcp_proxies']} TCP proxies" for name, v in sorted(inv.items()))
    return domains == 0 and proxies == 0, f"{domains} domains and {proxies} TCP proxies on {len(inv)} services", [
        ev("no domain and no proxy on postgres and nocodb", f"read from the Railway API at {audit['at'].replace('T', ' ').rstrip('Z')} UTC",
           "GraphQL: domains and tcpProxies, per service", rows)]


def row_web(c):
    anon, allowed, nopolicy = outside(c, "web.anonymous"), outside(c, "web.allowed"), outside(c, "web.other")
    x_anon, x_own, x_peer = outside(c, "web.anonymous", True), outside(c, "web.allowed", True), outside(c, "web.peer", True)
    cross = data[c]["outside_cross"]
    parts = (anon, allowed, x_anon, x_own, x_peer)
    ok = all(p and p["ok"] for p in parts)
    when = cross["at"].replace("T", " ").rstrip("Z")
    first = from_check(anon, "request without a token blocked")
    first["cmd"] += f"; checked at {data[c]['outside']['at'].replace('T', ' ').rstrip('Z')} UTC, environments running"
    items = [
        first,
        from_check(allowed, "this client's service token passes Access and NocoDB answers"),
        ev("the other client's valid service token blocked by Access", tidy("web.peer", x_peer["observed"]) if x_peer else "not run",
           f"{x_peer['cmd'] if x_peer else ''}; checked at {when} UTC, environments stopped",
           f"at the same time:\nno token: {tidy('', x_anon['observed'])}\nthis client's token: {tidy('', x_own['observed'])}" if x_anon and x_own else None),
    ]
    if nopolicy:
        items.append(from_check(nopolicy, "a token in no policy refused (same 403 as an invalid token)"))
    short = (f"No token HTTP {http_code(anon['observed'])}. Own token HTTP {http_code(allowed['observed'])} from NocoDB. "
             f"Other client's token HTTP {http_code(x_peer['observed']) if x_peer else '?'} from Access")
    return ok, short, items


def row_signup(c):
    attempt, control = inside(c, "signup.anonymous"), inside(c, "signup.control")
    status, said, before, after = signup_parts(attempt["observed"])
    ok = attempt["ok"] and control["ok"] and "Not allowed to signup" in said and before == after
    return ok, f"Rejected with HTTP {status}, users {before} before and {after} after", [from_check(control), from_check(attempt)]


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
    same = bool(replay.get("ok")) and replay["same_digest"] and not replay["created_on_replay"]
    items = [ev("bootstrap replayed: no duplicate objects, sample rows unchanged",
                f"state digest before {replay['before']['state_digest'][:16]}, after {replay['after']['state_digest'][:16]}; objects created on replay: {len(replay['created_on_replay'])}",
                "redeploy the bootstrap service; the digest covers roles, databases, NocoDB objects and the sample rows")]
    tail = "No duplicate objects; sample rows unchanged on replay" if same else "Replay created objects or changed sample rows"
    if c == B:
        diff = audit["config_diff"]
        items.insert(0, ev("stood up from the final reference without manual fixes", f"exit code {last_b['exit_code']} from an empty project, commit {last_b['commit']}",
                           "python3 provision/provision.py up beacon-hvac"))
        for stop in stopped_b:
            items.insert(1, ev("earlier attempt, on a previous commit", f"stopped at {stop['ended'].replace('T', ' ').rstrip('Z')} UTC by Railway: {stop['stopped_by']}", stop.get("note")))
        items.insert(len(stopped_b) + 1, ev("only identifier, domain and secrets differ", f"{len(diff)} differences left once those are masked", "normalized service settings and variables compared"))
        clean = last_b["exit_code"] == 0 and not diff
        head = "Completed without manual fixes" if clean else "Needed manual fixes"
        return same and clean, f"{head}. {tail}", items
    return same, f"Corrections carried into the reference. {tail}", items


def utc(stamp, seconds=False):
    return str(stamp).replace("T", " ")[:19 if seconds else 16] + " UTC"


def row_cron(c):
    cron = data[c]["cron"]
    result = cron["result"]
    when = (cron.get("scheduled_for") or "")[11:16]
    ok = bool(result.get("ok")) and cron["deployment_status"] == "SUCCESS"
    return ok, (f"Railway started it for {when} UTC; the job exited cleanly" if ok else f"Railway run for {when} UTC did not exit cleanly"), [
        ev("run triggered by Railway, clean finish", f"scheduled for {utc(cron.get('scheduled_for'))}, container started {utc(cron.get('container_started'), True)}, deployment status {cron['deployment_status']}",
           f"cron {cron['schedule_during_test']} for the test, back to {cron['reference_schedule']} UTC afterwards", json.dumps(result, indent=1, sort_keys=True))]


def row_backup(c):
    cron, restore = data[c]["cron"], data[c]["restore"]
    stored = cron["stored"]
    marker = restore["verify"].get("marker_nocodb")
    encrypted = stored["http"] == 200 and stored["sha256_match"] is True and stored["starts_with_age_header"] is True and stored["contains_plain_marker"] is False
    append_only = cron["write_token_cannot_read"] == 403 and cron["write_token_cannot_replace"] == 409
    race = concurrency["ok"] and concurrency["accepted"] == 1
    restored = bool(restore["verify"].get("ok")) and restore.get("destination_empty_before") is True
    ok = encrypted and append_only and race and restored
    problems = [text for flag, text in ((encrypted, "stored object not verified"), (append_only, "write token could read or replace a backup"),
                                        (race, "concurrent uploads not limited to one"), (restored, "test record not read back after restore")) if not flag]
    short = "Restored into a new project, client-specific test record read back through NocoDB" if ok else "; ".join(problems).capitalize()
    return ok, short, [
        ev("encrypted, stored off Railway", f"HTTP {stored['http']}; checksum {'matches' if stored['sha256_match'] else 'differs'}; age header {'present' if stored['starts_with_age_header'] else 'absent'}; "
                                            f"plain test-record text in the object: {yes(stored['contains_plain_marker'])}", "GET the object with the read token"),
        ev("environment can add a backup, not read or replace one", f"read with its token HTTP {cron['write_token_cannot_read']}, replace HTTP {cron['write_token_cannot_replace']}", "same object, write token"),
        ev("two uploads of one new key cannot both succeed",
           f"{concurrency['attempts']} concurrent uploads: {concurrency['accepted']} accepted (201), {concurrency['refused']} refused (409); content afterwards {'unchanged' if concurrency['content_unchanged'] else 'changed'}",
           f"sink redeployed with one conditional write, checked {utc(concurrency['at'])} on the test key {concurrency['test_key']}, then {'deleted' if concurrency.get('test_key_deleted') else 'kept'}"),
        ev("client-specific test record read through the restored NocoDB", f"{marker}, NocoDB {restore['verify'].get('nocodb_version')}",
           f"new project {restore['destination']}, same image digests", json.dumps(restore["restore"], indent=1, sort_keys=True))]


def row_manifest(c):
    images = audit["manifest"][c]
    deployed = audit["deployed_digests"][c]
    rows = "\n".join(f"{name}: {ref.split('@')[0]}\n  deployed {deployed.get(name)}" for name, ref in sorted(images.items()))
    ok = audit["manifest_identical"] and audit["manifest_matches_lock"] and audit["deployed_identical"] and audit["deployed_match_lock"]
    return ok, f"{len(images)} services on pinned digests, identical in both environments" if ok else "Deployed digests differ between environments or from the manifest", [
        ev("versions and digests deployed, identical between A and B",
           f"identical in both environments: {yes(audit['deployed_identical'])}; match the version manifest: {yes(audit['deployed_match_lock'])}", "deployment.meta.imageDigest, per service", rows),
        from_check(inside(c, "manifest.postgres_runtime")), from_check(inside(c, "manifest.nocodb_runtime"))]


ROWS = [
    ("Right source", "The expected tables and this client's test record are seen in NocoDB.", row_source),
    ("Read-only", "Read accepted, write refused with 42501, temp table refused, connection to nocodb_meta refused.", row_readonly),
    ("Future table", "A table created later by the load role is readable by the reader without a new grant.", row_future),
    ("Exposure", "API inventory: no domain and no proxy on postgres and nocodb.", row_exposure),
    ("Web access", "Requests without a token are blocked; this client's service token passes Access; the other client's valid token is blocked.", row_web),
    ("Sign-up", "A real anonymous sign-up is rejected.", row_signup),
    ("Across clients", "One private network does not reach the other; the other is healthy; all secret fingerprints differ.", row_across),
    ("Repeatable", "The second environment needs no manual fix; replaying the bootstrap creates no duplicate objects and leaves the sample rows unchanged.", row_repeat),
    ("Scheduled job", "A run triggered by Railway finishes cleanly.", row_cron),
    ("Backup", "Restored into a new destination on the same NocoDB version, client-specific test record read back in NocoDB.", row_backup),
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
    f"All {len(ROWS)} checks passed in both environments." if ok_count == len(ROWS) else f"{ok_count} of {len(ROWS)} checks passed in both environments.",
    "The second deployment completed without manual fixes." if clean_b else "The second deployment needed manual fixes: see line 8.",
    "A backup of each environment, restored into a new project, was read back through NocoDB." if restored else "Restore did not complete: see line 10.",
]
peak = max(data[c]["memory"]["nocodb"]["peak_gb"] for c in (A, B))
rest = max(data[c]["memory"]["nocodb"]["last_gb"] for c in (A, B))
second = outside(A, "web.second_login")
feasibility = os.path.join(ROOT, "runs", "feasibility", "nocodb_512mb.json")
memory_note = f"NocoDB 2026.10.1 reached {peak:.2f} GB in these two environments and rested near {rest:.2f} GB."
if os.path.exists(feasibility):
    probe = json.load(open(feasibility))
    if probe.get("started_under_limit") is False:
        memory_note += (f" In a feasibility test under a {probe['memory_limit_gb'] * 1000:.0f} MB service limit it did not start in the settings tried "
                        f"(<a href=\"{REPO}/blob/main/runs/feasibility/nocodb_512mb.json\">record</a>).")
notes = [
    e("Private tunnel rather than a public Railway domain: a second public path would go around Access."),
    e(f"Access in front of NocoDB Community leaves a second login: a token that passes Access still gets HTTP {http_code(second['observed'])} from NocoDB."),
    e("Access was tested with service tokens. Human sign-in was not tested."),
    'Since 9 January 2026 the <a href="https://nocodb.com/docs/product-docs/getting-started/license">NocoDB license</a> reads: '
    "“Internal self-hosting does not require a commercial license”, while a commercial license is needed to "
    "“Offer NocoDB as a hosted or managed service” or to “Provide direct NocoDB access to external customers”. "
    "The question is who uses NocoDB, and who owns the instances.",
    e("QuickBooks webhooks need a non-interactive endpoint with signature validation. The OAuth callback route must be tested separately."),
    e("Read-only NocoDB is a choice for this example, not a rule of the setup. Edits would need a role with write grants."),
    "On NocoDB 2026.10.1, NC_INVITE_ONLY_SIGNUP=true left sign-up open on the first run: HTTP 200 and users 1 to 2 "
    f'(<a href="{REPO}/blob/02f76ee/runs/20261101/acme-mech/inside.json">first-run checks, commit 02f76ee</a>). '
    "The bootstrap now sets the admin setting and checks it before the tunnel starts.",
    memory_note if os.path.exists(feasibility) else e(memory_note),
    e("Railway cron schedules are in UTC, so the local time of a backup moves with daylight saving."),
    e("Outside this example: real QuickBooks; GitHub repositories, teams and access per client; n8n."),
]


def span(first, last):
    if first == last:
        return first.strftime("%-d %B %Y")
    if (first.year, first.month) == (last.year, last.month):
        return f"{first.strftime('%-d')} to {last.strftime('%-d %B %Y')}"
    if first.year == last.year:
        return f"{first.strftime('%-d %B')} to {last.strftime('%-d %B %Y')}"
    return f"{first.strftime('%-d %B %Y')} to {last.strftime('%-d %B %Y')}"


def git(*args):
    return subprocess.check_output(["git", "-C", ROOT, *args], text=True).strip()


first = dt.datetime.strptime(RUN, "%Y%m%d").date()
last = dt.date.fromisoformat(audit["at"][:10])
date = span(first, last)
lock = audit["lock"]
# The manifest commit is the one whose versions.lock.json matches what the audit read, not whatever HEAD holds.
manifest_commit = next((h for h in git("log", "--format=%h", "--", "reference/versions.lock.json").split()
                        if {k: v["ref"] for k, v in json.loads(git("show", f"{h}:reference/versions.lock.json")).items()} == lock), None)
if not manifest_commit:
    refuse("no commit of reference/versions.lock.json matches the manifest the audit read")
same_manifest_b = subprocess.run(["git", "-C", ROOT, "diff", "--quiet", manifest_commit, last_b["commit"], "--", "reference/versions.lock.json"]).returncode == 0
hardened = git("log", "-1", "--format=%h", "--", "checks", "ops", "provision", "sink")
hardened_after_run = subprocess.run(["git", "-C", ROOT, "merge-base", "--is-ancestor", last_b["commit"], hardened]).returncode == 0 and hardened != last_b["commit"]
provenance = f"Results from the runs of {span(first, last).replace(' to ', ' and ')} (commit {last_b['commit']})."
if hardened_after_run:
    provenance += f" Scripts hardened afterwards (commit {hardened}), tested locally; not re-run on Railway."
cross_at = utc(data[A]["outside_cross"]["at"])
if teardown:
    after = f"Removed after the run, on {dt.datetime.strptime(teardown['date'], '%Y-%m-%d').strftime('%-d %B %Y')}"
else:
    after = "Up for the length of the run, then stopped"
values = {
    "date": e(date), "commit": e(manifest_commit), "commit_url": f"{REPO}/blob/{manifest_commit}/reference/versions.lock.json",
    "manifest_note": e(f"beacon-hvac was stood up from {last_b['commit']}, which carries this manifest unchanged." if same_manifest_b else
                       f"beacon-hvac was stood up from {last_b['commit']}, whose manifest differs."),
    "provenance": e(provenance),
    "later_checks": e(f"The cross-client Access check (line 5) and the backup sink concurrency check (line 10) ran after the environments were stopped, "
                      f"at {cross_at[11:16]} and {concurrency['at'][11:16]} UTC on {dt.date.fromisoformat(concurrency['at'][:10]).strftime('%-d %B')}, with the hardened scripts."),
    "v_postgres": e(first_word(inside(A, "manifest.postgres_runtime")["observed"])),
    "v_nocodb": e(inside(A, "manifest.nocodb_runtime")["observed"]),
    "v_cloudflared": e(audit["cloudflared_runtime"][A] or re.search(r":([0-9.]+)@", lock["cloudflared"]).group(1)),
    "findings": "\n    ".join(f'<p class="finding">{e(f)}</p>' for f in findings),
    "rows": "\n".join(rows_html),
    "notes": "\n      ".join(f"<li>{n}</li>" for n in notes),
    "teardown": e(after), "repo_url": REPO,
}
with open(os.path.join(ROOT, "report/template.html")) as fh:
    page = fh.read()
for key, value in values.items():
    page = page.replace("{{" + key + "}}", value)
if "{{" in page:
    refuse("template placeholder left unfilled: " + re.search(r"\{\{\w+\}\}", page).group(0))
site = os.path.join(ROOT, "page/site")
os.makedirs(site, exist_ok=True)
with open(os.path.join(site, "index.html"), "w") as fh:
    fh.write(page)
for name in ("style.css", "page.js"):
    shutil.copy(os.path.join(ROOT, "report", name), os.path.join(site, name))
print(f"{ok_count}/{len(ROWS)} lines; page/site/index.html written")
