# railway-nocodb-client-env

One Railway project and one NocoDB per client, stood up from this reference: private Postgres, NocoDB on restricted roles, Cloudflare Tunnel with Access, an idempotent bootstrap, a scheduled encrypted backup. Two fictional environments, `acme-mech` and `beacon-hvac`, were built from it and checked. Their outputs are in `runs/20261101/`, and the report is generated from those files by `report/build.py`.

This is a reference to lay over an existing template, not a replacement for one.

## What it sets up

| Service | Role |
|---|---|
| `postgres` | Private, no TCP proxy. Databases `client_data` and `nocodb_meta`. Roles: load, NocoDB metadata, NocoDB read, backup |
| `nocodb` | Pinned tag and digest, no public domain, read-only source |
| `cloudflared` | One tunnel per project, with Protect with Access and the application audience |
| `bootstrap` | One-shot. Waits for its dependencies, fails clearly, safe to replay |
| `backup` | Cron at 08:17 UTC. `pg_dump` of both databases, encrypted to a public age key, sent off Railway |
| `checks` | One-shot. Runs the checks from inside the private network |

`bootstrap`, `backup` and `checks` share one image, `ops/Dockerfile`, built from the same Postgres digest as the server. Versions and digests are in `reference/versions.lock.json`.

## Replay

Needs `RAILWAY_API_TOKEN`, `RAILWAY_WORKSPACE_ID`, `CLOUDFLARE_API_TOKEN`, and `age` installed locally. Deploy `sink/` first, or point `BACKUP_SINK_URL` at your own store. Domain names are in `reference/clients/` and the `ZONE` constant.

    python3 provision/provision.py up acme-mech
    python3 provision/prove.py checks acme-mech
    python3 provision/prove.py outside acme-mech
    python3 provision/prove.py replay acme-mech
    python3 provision/prove.py cron acme-mech
    python3 provision/prove.py restore acme-mech
    python3 provision/prove.py audit
    python3 report/build.py 20261101
    python3 provision/provision.py down acme-mech

Generated secrets stay in `.secrets/<client>.json`, which is git-ignored. Keep the age identity and `NC_CONNECTION_ENCRYPT_KEY` outside Railway: a backup cannot be used without them.

## Using the checks on another template

`checks/` does not depend on the provisioning code.

- `check_inside.py` needs `psycopg` and environment variables. Run it as a one-shot service inside the private network.
- `check_outside.py` needs only the standard library. Run it from anywhere against a hostname behind Access.

## What the first environment corrected

- The private endpoint of a service exists only after its first deployment, so it is renamed after that.
- `NC_INVITE_ONLY_SIGNUP=true` left sign-up open on NocoDB 2026.10.1. The bootstrap now sets the admin setting and checks it before the tunnel starts.
- A volume added to a running service redeploys it, so the volume is created before the image is set.

## Railway limit met during the run

On 2026-11-01 at 15:38 UTC, `serviceCreate` for the second environment was refused by the Railway API: `You've hit the service creation limit for new accounts (25 services per day). Contact us at station.railway.com to raise this.` This is a daily account quota, not a fault in the reference. Railway does not document when it resets. Attempts are recorded in `runs/20261101/beacon-hvac/up_attempts.json`. No workaround was used.

## Out of scope

Real QuickBooks, a GitHub organization per client, n8n. Read-only NocoDB is a choice for this example. Nothing here is a compliance statement.
