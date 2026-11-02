// node --test tests/sink.test.mjs: the sink Worker against an in-memory R2 that lets two requests interleave.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../sink/worker.js';

class FakeR2 {
  constructor() { this.objects = new Map(); }
  async head(key) { await new Promise((r) => setTimeout(r, 5)); return this.objects.has(key) ? { key } : null; }
  async put(key, body, options = {}) {
    const text = await new Response(body).text();
    await new Promise((r) => setTimeout(r, 5)); // the write lands later; the condition is checked when it lands
    const cond = options.onlyIf;
    const ifNoneMatch = cond && (typeof cond.get === 'function' ? cond.get('If-None-Match') : cond.etagDoesNotMatch);
    if (ifNoneMatch === '*' && this.objects.has(key)) return null; // evaluated with the write, as R2 does
    this.objects.set(key, text);
    return { key };
  }
  async get(key) { return this.objects.has(key) ? { body: this.objects.get(key) } : null; }
  async list({ prefix, cursor }) {
    const keys = [...this.objects.keys()].filter((k) => k.startsWith(prefix)).sort();
    const start = cursor ? Number(cursor) : 0;
    const page = keys.slice(start, start + 1000);
    const truncated = start + 1000 < keys.length;
    return { objects: page.map((key) => ({ key, size: this.objects.get(key).length })), truncated, cursor: truncated ? String(start + 1000) : undefined };
  }
}

const env = () => ({ BACKUPS: new FakeR2(), WRITE_ACME_MECH: 'w-token', READ_ACME_MECH: 'r-token' });
const call = (e, method, path, token, body) =>
  worker.fetch(new Request('https://sink.example' + path, { method, body, headers: { authorization: 'Bearer ' + token } }), e);

test('two concurrent uploads of one key: exactly one is stored, the first content stays', async () => {
  const e = env();
  const answers = await Promise.all(['first', 'second', 'third'].map((b) => call(e, 'PUT', '/acme-mech/20261102T155517Z.tar.age', 'w-token', b)));
  const codes = answers.map((r) => r.status).sort();
  assert.deepEqual(codes, [201, 409, 409]);
  const stored = e.BACKUPS.objects.get('acme-mech/20261102T155517Z.tar.age');
  const again = await call(e, 'PUT', '/acme-mech/20261102T155517Z.tar.age', 'w-token', 'later');
  assert.equal(again.status, 409);
  assert.equal(e.BACKUPS.objects.get('acme-mech/20261102T155517Z.tar.age'), stored);
});

test('the write token cannot read, the read token cannot write', async () => {
  const e = env();
  assert.equal((await call(e, 'PUT', '/acme-mech/a.tar.age', 'w-token', 'x')).status, 201);
  assert.equal((await call(e, 'GET', '/acme-mech/a.tar.age', 'w-token')).status, 403);
  assert.equal((await call(e, 'PUT', '/acme-mech/b.tar.age', 'r-token', 'x')).status, 403);
  assert.equal((await call(e, 'GET', '/beacon-hvac/', 'r-token')).status, 403);
});

test('the listing returns every object past the first 1000', async () => {
  const e = env();
  for (let i = 0; i < 1100; i++) e.BACKUPS.objects.set(`acme-mech/${String(i).padStart(5, '0')}.tar.age`, 'x');
  const listing = await (await call(e, 'GET', '/acme-mech/', 'r-token')).json();
  assert.equal(listing.keys.length, 1100);
});
