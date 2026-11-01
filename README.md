# railway-nocodb-client-env

One Railway project and one NocoDB per client, stood up from this reference: private Postgres, NocoDB on restricted roles, Cloudflare Tunnel and Access in front, an idempotent bootstrap, and a scheduled encrypted backup.

Work in progress.

## Railway limit met during the run

On 2026-11-01 at 15:38 UTC, `serviceCreate` for the second environment was refused by the Railway API: `You've hit the service creation limit for new accounts (25 services per day). Contact us at station.railway.com to raise this.` This is a daily account quota, not a fault in the reference. Railway does not document when it resets. The attempt is recorded in `runs/20261101/beacon-hvac/up_attempts.json`. No workaround was used.
