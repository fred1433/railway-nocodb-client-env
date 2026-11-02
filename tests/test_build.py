"""report/build.py on a clone of this checkout with altered run outputs."""
import json, os, re, shutil, subprocess, sys

import pytest

from fakes import ROOT

RUN = "20261101"


@pytest.fixture
def clone(tmp_path):
    dest = tmp_path / "repo"
    subprocess.run(["git", "clone", "-q", "--no-hardlinks", ROOT, str(dest)], check=True)
    for part in ("report", "runs", "reference", "checks", "ops", "provision", "sink"):
        shutil.rmtree(dest / part, ignore_errors=True)
        shutil.copytree(os.path.join(ROOT, part), dest / part, ignore=shutil.ignore_patterns("__pycache__"))
    return dest


def build(clone, run=RUN):
    out = subprocess.run([sys.executable, str(clone / "report" / "build.py"), run], capture_output=True, text=True, cwd=clone)
    page = clone / "page" / "site" / "index.html"
    return out, page.read_text() if page.exists() and out.returncode == 0 else ""


def edit(clone, rel, fn, run=RUN):
    path = clone / "runs" / run / rel
    data = json.load(open(path))
    fn(data)
    json.dump(data, open(path, "w"))


def cell(page, number, client):
    row = page.split(f'<span class="num">{number}</span>', 1)[1].split("</summary>", 1)[0]
    return row.split(f'<span class="client-tag">{client}</span>', 1)[1].split("</span></span>", 1)[0], row


def test_archived_run_builds(clone):
    out, page = build(clone)
    assert out.returncode == 0, out.stderr[-400:]
    assert "11/11" in out.stdout


def test_missing_proof_refused(clone):
    os.remove(clone / "runs" / RUN / "beacon-hvac" / "memory.json")
    out, _ = build(clone)
    assert out.returncode != 0


def test_restore_of_another_backup_refused(clone):
    edit(clone, "acme-mech/restore.json", lambda d: d["restore"].update(key="acme-mech/20261031T081700Z.tar.age"))
    out, _ = build(clone)
    assert out.returncode != 0


def test_proof_of_another_run_refused(clone):
    edit(clone, "beacon-hvac/outside_cross.json", lambda d: d.update(run="20990101"))
    out, _ = build(clone)
    assert out.returncode != 0


def test_failed_restore_is_not_written_as_restored(clone):
    edit(clone, "acme-mech/restore.json", lambda d: d["verify"].update(ok=False, marker_nocodb=None))
    out, page = build(clone)
    text, _ = cell(page, 10, "acme-mech")
    assert "Restored" not in text


def test_accepted_replace_fails_the_backup_line(clone):
    edit(clone, "acme-mech/cron.json", lambda d: d.update(write_token_cannot_replace=201))
    out, page = build(clone)
    _, row = cell(page, 10, "acme-mech")
    assert 'class="cell cell-a bad"' in row


def test_date_across_two_months(clone):
    shutil.copytree(clone / "runs" / RUN, clone / "runs" / "20261030")
    for path in (clone / "runs" / "20261030").rglob("*.json"):
        data = json.load(open(path))
        if isinstance(data, dict) and "run" in data:
            data["run"] = "20261030"
            json.dump(data, open(path, "w"))
    out, page = build(clone, "20261030")
    assert out.returncode == 0, out.stderr[-300:]
    assert "30 October to 2 November 2026" in page


def test_no_python_traces_on_the_page(clone):
    out, page = build(clone)
    text = re.sub(r"<[^>]+>", " ", page)
    for trace in ("None", "True", "False", "finished SUCCESS", "If y;", "If y "):
        assert trace not in text, trace
