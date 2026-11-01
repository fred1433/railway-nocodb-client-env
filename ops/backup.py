"""Dumps both databases, encrypts to a public age key, sends the result off Railway, exits cleanly."""
import hashlib, json, os, subprocess, tarfile, tempfile, time
from common import PGHOST, PGPORT, die, emit, wait_for_postgres

E = os.environ
USER = "backup_runner"
env = dict(E, PGPASSWORD=E["BACKUP_PASSWORD"])
stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
emit("JOB_START", job="backup", client=E["CLIENT_ID"], stamp=stamp)
wait_for_postgres(USER, E["BACKUP_PASSWORD"], "client_data")


def run(cmd, stage):
    try:
        subprocess.run(cmd, env=env, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        die(stage, (exc.stderr or "").strip()[-250:])


with tempfile.TemporaryDirectory() as tmp:
    sizes = {}
    for db in ("client_data", "nocodb_meta"):
        path = f"{tmp}/{db}.dump"
        run(["pg_dump", "-h", PGHOST, "-p", str(PGPORT), "-U", USER, "-Fc", "-d", db, "-f", path], "pg_dump_" + db)
        sizes[db] = os.path.getsize(path)
    version = subprocess.check_output(["pg_dump", "--version"], text=True).strip()
    with open(f"{tmp}/manifest.json", "w") as fh:
        json.dump({"client": E["CLIENT_ID"], "stamp": stamp, "pg_dump": version, "dumps": sizes}, fh)
    tar_path = f"{tmp}/bundle.tar"
    with tarfile.open(tar_path, "w") as tar:
        for name in ("client_data.dump", "nocodb_meta.dump", "manifest.json"):
            tar.add(f"{tmp}/{name}", arcname=name)
    out = f"{tmp}/bundle.tar.age"
    run(["age", "-r", E["BACKUP_AGE_RECIPIENT"], "-o", out, tar_path], "encrypt")
    with open(out, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
        fh.seek(0)
        header = fh.read(21).decode("ascii", "replace")
    key = f"{E['CLIENT_ID']}/{stamp}.tar.age"
    status = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "120", "-X", "PUT",
                             "-H", f"Authorization: Bearer {E['BACKUP_SINK_TOKEN']}", "--data-binary", f"@{out}",
                             f"{E['BACKUP_SINK_URL'].rstrip('/')}/{key}"], capture_output=True, text=True)
    if status.stdout.strip() != "201":
        die("upload", f"HTTP {status.stdout.strip()} {status.stderr.strip()[:160]}")
    emit("JOB_RESULT", ok=True, job="backup", key=key, encrypted_bytes=os.path.getsize(out), sha256=digest,
         age_header=header, dumps=sizes, pg_dump=version)
