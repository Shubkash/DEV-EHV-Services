import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const publicDir = new URL('../public/', import.meta.url);

test('public site contains the enquiry spam trap and search metadata', async () => {
  const page = await readFile(new URL('index.html', publicDir), 'utf8');
  assert.match(page, /name="website"/);
  assert.match(page, /meta name="description"/);
  assert.match(page, /application\/ld\+json/);
});

test('admin dates are parsed as supplied by the API', async () => {
  const page = await readFile(new URL('admin.html', publicDir), 'utf8');
  assert.match(page, /new Date\(x\.created_at\)/);
  assert.doesNotMatch(page, /created_at\+'Z'/);
});
