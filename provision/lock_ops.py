#!/usr/bin/env python3
"""Pin the ops image built for a commit: anonymous pull token, manifest digest, versions.lock.json."""
import json, os, sys, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = "fred1433/railway-nocodb-client-env/ops"
sha = sys.argv[1]
token = json.load(urllib.request.urlopen(f"https://ghcr.io/token?scope=repository:{REPO}:pull"))["token"]
req = urllib.request.Request(f"https://ghcr.io/v2/{REPO}/manifests/{sha}", method="HEAD", headers={
    "Authorization": "Bearer " + token,
    "Accept": "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json"})
digest = urllib.request.urlopen(req).headers["Docker-Content-Digest"]
path = os.path.join(ROOT, "reference/versions.lock.json")
lock = json.load(open(path))
lock["ops"]["ref"] = f"ghcr.io/{REPO}@{digest}"
lock["ops"]["commit"] = sha
with open(path, "w") as fh:
    json.dump(lock, fh, indent=2)
    fh.write("\n")
print(lock["ops"]["ref"])
