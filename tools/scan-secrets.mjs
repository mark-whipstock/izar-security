// Pre-commit secret scanner. Checks staged files (or the whole tree with --all)
// for API keys and JWTs. No dependencies.
//
// Enable the hook once per clone: git config core.hooksPath tools
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const PATTERNS = [
  // Supabase keys and Printify tokens are both JWTs.
  { name: 'JWT', re: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { name: 'Stripe secret key', re: /[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/g },
  { name: 'Stripe webhook secret', re: /whsec_[A-Za-z0-9]{16,}/g },
  { name: 'Supabase service role marker', re: /service_role["']?\s*[:=]\s*["']eyJ/g },
];

const SKIP = /^(node_modules\/|dist\/|public\/mockups\/)|\.(png|jpg|jpeg|webp|gif|ico|woff2?|wasm|pdf|zip|lock)$|^(package-lock\.json|pnpm-lock\.yaml)$/i;

function git(...args) {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

const all = process.argv.includes('--all');
const files = (all
  ? git('ls-files')
  : git('diff', '--cached', '--name-only', '--diff-filter=ACM')
).split('\n').filter((f) => f && !SKIP.test(f));

let bad = 0;
for (const file of files) {
  let text;
  try {
    text = all ? readFileSync(file, 'utf8') : git('show', `:${file}`);
  } catch {
    continue;
  }

  for (const { name, re } of PATTERNS) {
    for (const match of text.matchAll(re)) {
      const line = text.slice(0, match.index).split('\n').length;
      console.error(`BLOCKED  ${file}:${line}  ${name}: ${match[0].slice(0, 24)}...`);
      bad += 1;
    }
  }
}

if (bad > 0) {
  console.error(`\n${bad} secret-looking string(s) found. Move them to .dev.vars / host env vars.`);
  console.error('If this is a certain false positive, commit with --no-verify (and be sure).');
  process.exit(1);
}
