// Tests for tools/scan-secrets.mjs.
//
// Fixtures are built by string concatenation so this file doesn't trip the
// scanner itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, cpSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCANNER = join(HERE, '..', 'tools', 'scan-secrets.mjs');

/** Runs the scanner in a temporary git repo containing `files`. */
function scan(files) {
  const dir = mkdtempSync(join(tmpdir(), 'scan-secrets-'));
  try {
    const git = (...a) => execFileSync('git', a, { cwd: dir, encoding: 'utf8' });
    git('init', '-q');
    git('config', 'user.email', 'test@example.invalid');
    git('config', 'user.name', 'test');

    for (const [name, body] of Object.entries(files)) {
      const full = join(dir, name);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, body);
    }
    mkdirSync(join(dir, 'tools'), { recursive: true });
    cpSync(SCANNER, join(dir, 'tools', 'scan-secrets.mjs'));
    git('add', '-A');

    try {
      const out = execFileSync('node', ['tools/scan-secrets.mjs'], {
        cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      });
      return { code: 0, stderr: out };
    } catch (e) {
      return { code: e.status ?? 1, stderr: (e.stderr ?? '') + (e.stdout ?? '') };
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('clean files pass', () => {
  const r = scan({ 'src/app.ts': 'export const greet = () => "hello";\n' });
  assert.equal(r.code, 0, r.stderr);
});

test('blocks a Stripe live secret key', () => {
  const key = 'sk_' + 'live_' + 'A'.repeat(24);
  const r = scan({ 'config.ts': `export const K = "${key}";\n` });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /Stripe secret key/);
});

test('blocks a Stripe webhook secret', () => {
  const key = 'whsec_' + 'B'.repeat(24);
  const r = scan({ '.env.local.ts': `const s = "${key}";\n` });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /Stripe webhook secret/);
});

test('blocks a JWT (Supabase service key / Printify token shape)', () => {
  const jwt = 'eyJ' + 'a'.repeat(24) + '.' + 'b'.repeat(16) + '.' + 'c'.repeat(16);
  const r = scan({ 'notes.md': `token: ${jwt}\n` });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /JWT/);
});

test('skips vendored and binary paths', () => {
  const key = 'sk_' + 'live_' + 'C'.repeat(24);
  const r = scan({ 'node_modules/pkg/index.js': `const k = "${key}";\n` });
  assert.equal(r.code, 0, r.stderr);
});
