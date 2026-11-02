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

## Rebuild the archived report

Nothing is deployed:

    python3 report/build.py 20261101

The builder refuses to run when a proof is missing or belongs to another run.

## Prerequisites for a new run

- Railway: a plan above Free. Free allows one project and three services, and NocoDB 2026.10.1 did not start under its 512 MB service limit in the settings tried (`runs/feasibility/nocodb_512mb.json`). In the runs here NocoDB peaked near 1 GB. New accounts can also meet a daily service-creation limit (see below).
- Cloudflare: a zone for the hostnames, Zero Trust (Access) on the account, R2 for the backup sink, and an API token that can manage tunnels, Access applications, policies and service tokens, DNS records in the zone, and the sink Worker and its secrets.
- Locally: Python 3.11 or later, `age`, Node for `wrangler`. Hostnames are in `reference/clients/` and the `ZONE` constant in `provision/provision.py`.
- Environment: `RAILWAY_API_TOKEN`, `RAILWAY_WORKSPACE_ID`, `CLOUDFLARE_API_TOKEN`.
- The ops image: the digest pinned in `reference/versions.lock.json` is the one the published runs used. The scripts hardened after the run are not in it. The `ops-image` workflow builds an image for each push; pin it before a new run with `python3 provision/lock_ops.py <commit>`.

## A full run

Use one explicit run id for every command. `provision.py` and `prove.py` share the same default (`RUN_ID`, else today's UTC date), but passing `--run` keeps all outputs in one folder.

    RUN=20261215
    (cd sink && npx wrangler deploy)
    python3 provision/provision.py up acme-mech --run $RUN
    python3 provision/provision.py up beacon-hvac --run $RUN
    python3 provision/prove.py checks acme-mech --run $RUN
    python3 provision/prove.py checks beacon-hvac --run $RUN
    python3 provision/prove.py checks acme-mech --run $RUN      # again, now that the peer addresses are known
    for c in acme-mech beacon-hvac; do
      for p in outside replay cron restore memory; do python3 provision/prove.py $p $c --run $RUN || exit 1; done
    done
    python3 provision/prove.py audit --run $RUN
    python3 provision/prove.py stop acme-mech --run $RUN
    python3 provision/prove.py stop beacon-hvac --run $RUN
    python3 provision/prove.py outside-cross acme-mech --run $RUN    # NocoDB stopped: own token passes Access, the other client's is refused
    python3 provision/prove.py outside-cross beacon-hvac --run $RUN
    python3 sink/check_concurrency.py acme-mech --run $RUN
    python3 report/build.py $RUN
    python3 provision/provision.py down acme-mech
    python3 provision/provision.py down beacon-hvac

Every proof exits 1 when it fails. `restore` restores the backup that this run's `cron` stored (or `--key`), into a project created for that attempt, and deletes only that project. `provision.py up` records each attempt in `runs/<run>/<client>/up_attempts.json`.

## Secrets

Generated secrets stay in `.secrets/<client>.json`, which is git-ignored. During a restore the age identity enters the temporary restore project, because the restore job decrypts there. Keep a recovery copy of the age identity and of `NC_CONNECTION_ENCRYPT_KEY` independent of Railway: a backup cannot be used without them.

`sink/` is the minimal backup receptacle of this test bench: one conditional write per key, a write token for the environment, a read token for the operator. In production, use an object store with object lock or retention.

## Using the checks on another template

`checks/` does not depend on the provisioning code.

- `check_inside.py` needs `psycopg` and environment variables. Run it as a one-shot service inside the private network.
- `check_outside.py` needs only the standard library. Run it from anywhere against a hostname behind Access. A refusal counts only when Access itself answers.

## Tests

The scripts were hardened after the published run and tested locally, not re-run on Railway: a local Postgres 18, a fake NocoDB, a fake sink, a fake Railway API, and the sink Worker under Node with an in-memory R2.

    pip install "psycopg[binary]" pytest
    PG_BIN=/path/to/postgresql-18/bin pytest tests
    node --test tests/sink.test.mjs

## What the first environment corrected

- The private endpoint of a service exists only after its first deployment, so it is renamed after that.
- `NC_INVITE_ONLY_SIGNUP=true` left sign-up open on NocoDB 2026.10.1. The bootstrap now sets the admin setting and checks it before the tunnel starts.
- Creating the volume after the image started a second deployment on the same volume, so the volume now comes first.
- The Railway `projects` query needs the workspace argument: without it the list came back empty, each run created a new project, and that used up the daily service quota.
- `pg_dump` does not carry database-level grants, so the restore job applies them again.

## Railway limit met during the run

On 2026-11-01 at 15:38 UTC, `serviceCreate` for the second environment was refused by the Railway API: `You've hit the service creation limit for new accounts (25 services per day).` Earlier provisioning retries created duplicate projects and consumed the service-creation quota. After fixing project lookup, the second environment completed on 2 November from commit 1bc94a8 without further repairs. Attempts are recorded in `runs/20261101/beacon-hvac/up_attempts.json`.

## Out of scope

Real QuickBooks; GitHub repositories, teams and access per client; n8n. QuickBooks webhooks need a non-interactive endpoint with signature validation, and the OAuth callback route must be tested separately. Read-only NocoDB is a choice for this example. Access was tested with service tokens; human sign-in was not tested. Nothing here is a compliance statement.

## License

MIT for the scripts in this repository (`LICENSE`). NocoDB, Postgres, cloudflared and the other components keep their own licenses.
