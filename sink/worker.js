// Backup sink in front of one R2 bucket. Railway holds the write token only: an environment can add a
// backup, never read or replace one. The read token stays with the operator and the restore job.
const envKey = (prefix, client) => `${prefix}_${client.toUpperCase().replace(/-/g, '_')}`;
export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const match = pathname.match(/^\/([a-z0-9-]+)\/([A-Za-z0-9._-]*)$/);
    if (!match) return new Response('not found', { status: 404 });
    const [, client, object] = match;
    const bearer = (request.headers.get('authorization') || '').replace(/^Bearer /, '');
    const can = (name) => bearer.length > 0 && env[envKey(name, client)] === bearer;
    const key = `${client}/${object}`;
    if (request.method === 'PUT' && object && can('WRITE')) {
      if (await env.BACKUPS.head(key)) return new Response('exists', { status: 409 });
      await env.BACKUPS.put(key, request.body);
      return new Response('stored', { status: 201 });
    }
    if (request.method === 'GET' && can('READ')) {
      if (!object) {
        const list = await env.BACKUPS.list({ prefix: `${client}/` });
        return Response.json({ keys: list.objects.map((o) => o.key), sizes: list.objects.map((o) => o.size) });
      }
      const found = await env.BACKUPS.get(key);
      return found ? new Response(found.body) : new Response('not found', { status: 404 });
    }
    return new Response('forbidden', { status: 403 });
  },
};
