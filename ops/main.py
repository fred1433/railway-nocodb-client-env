"""Entry point of the ops image. OPS_JOB selects the job, so one image serves every one-shot service."""
import os, runpy, sys

JOBS = {
    "bootstrap": "/app/ops/bootstrap.py",
    "backup": "/app/ops/backup.py",
    "restore": "/app/ops/restore.py",
    "restore-verify": "/app/ops/restore_verify.py",
    "checks": "/app/checks/check_inside.py",
}
job = os.environ.get("OPS_JOB", "")
if job not in JOBS:
    sys.exit(f"OPS_JOB must be one of {sorted(JOBS)}, got {job!r}")
sys.path.insert(0, "/app/ops")
try:
    runpy.run_path(JOBS[job], run_name="__main__")
except Exception as exc:  # type only: a subprocess error text can carry its command line, and so a token
    print('JOB_RESULT {"ok": false, "stage": "unhandled", "detail": "%s"}' % type(exc).__name__, flush=True)
    sys.exit(1)
