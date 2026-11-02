// Minimal backup sink for this test bench, in front of one R2 bucket. Railway holds the write token only: an
// environment can add a backup, never read or replace one. The read token stays with the operator and the restore job.
// In production, use an object store with object lock or retention instead of this Worker.
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
      // One conditional write: R2 evaluates If-None-Match: * atomically and returns null when the key exists,
      // so two concurrent uploads of the same key cannot both succeed.
      const stored = await env.BACKUPS.put(key, request.body, { onlyIf: new Headers({ 'If-None-Match': '*' }) });
      return stored ? new Response('stored', { status: 201 }) : new Response('exists', { status: 409 });
    }
    if (request.method === 'GET' && can('READ')) {
      if (!object) {
        const keys = [], sizes = [];
        let cursor;
        do {
          const page = await env.BACKUPS.list({ prefix: `${client}/`, cursor });
          page.objects.forEach((o) => { keys.push(o.key); sizes.push(o.size); });
          cursor = page.truncated ? page.cursor : undefined;
        } while (cursor);
        return Response.json({ keys, sizes });
      }
      const found = await env.BACKUPS.get(key);
      return found ? new Response(found.body) : new Response('not found', { status: 404 });
    }
    return new Response('forbidden', { status: 403 });
  },
};
