# izar-security

Security tooling and patterns from [Izar](https://izarflags.com), a production
e-commerce marketplace I built and run: a browser vector editor and
print-on-demand storefront with Stripe payments and seller payouts.

Izar's source is private because it handles real payments and customer data.
This repo holds the parts that are useful on their own: a secret scanner, the
CI check that runs it, and the MFA gate used on privileged endpoints. It was
started with a fresh history, so nothing from the private repo is in it.

## Contents

| Path | What it is |
|---|---|
| `tools/scan-secrets.mjs` | Pre-commit secret scanner, no dependencies |
| `tools/pre-commit` | Git hook that runs the scanner on staged files |
| `test/scan-secrets.test.mjs` | Tests for the scanner |
| `examples/adminAuth.ts` | MFA (aal2) step-up checks for sensitive actions |
| `.github/workflows/security.yml` | CI: scans the whole tree and runs the tests |

## 1. Secret scanning

`tools/scan-secrets.mjs` blocks a commit if any staged file contains something
that looks like a secret. It runs on plain Node with no network access, so it
stops the commit before anything reaches a remote.

```bash
git config core.hooksPath tools     # enable the hook once per clone
node tools/scan-secrets.mjs --all   # scan the whole working tree
```

It blocks on JWTs (Supabase keys, Printify tokens), Stripe secret keys
(`sk_live_...`, `rk_live_...`), Stripe webhook secrets (`whsec_...`) and
`service_role` assignments. Lockfiles, binaries and `node_modules` are skipped.

The tests run the scanner against throwaway git repos. Their fake keys are
built by string concatenation at runtime, so the test file never contains a
key-shaped string and doesn't trip the scanner itself.

## 2. MFA step-up for sensitive actions

`examples/adminAuth.ts` is the check Izar's server endpoints use before
sensitive actions. The Supabase JWT signature is already verified before these
helpers run. What they add is a check on *how* the user signed in: a valid
session from a phished password is `aal1`, and on an account with 2FA it
shouldn't be able to publish, delete the account, or request a payout.

- `requireAal2` is used on admin actions (order fulfilment, payout marking,
  listing review, report takedowns), after a role check. It requires `aal2`
  every time, without checking whether the account has 2FA set up, so it
  can't be bypassed if that information is missing.
- `mfaStepUp` is the softer check for sellers: publishing, unpublishing,
  payout requests, profile changes and account deletion. Accounts with 2FA
  must have used it this session; accounts without 2FA pass.
- `tokenAal` treats any token it can't parse as `aal1`, so a malformed token
  gets less access, not more.

## 3. Database authorization

Izar's tables use PostgreSQL row-level security. Anything involving money,
publishing or customer data goes through the server: publishing and payout
requests are database functions that clients aren't allowed to call directly,
and order records (which hold shipping addresses) can't be read by clients at
all, only through a view with the personal columns removed. Low-risk social
actions like follows and favorites are written by the client, with policies
that only allow a user to act as themselves. The general pattern for a locked
table:

```sql
alter table public.listings enable row level security;

-- Anyone can read published listings.
create policy listings_public_read on public.listings
  for select using (status = 'published');

-- Sellers can read their own drafts.
create policy listings_owner_read on public.listings
  for select using (auth.uid() = owner_id);

-- No client writes. Changes go through the service role on the server.
revoke insert, update, delete on public.listings from anon, authenticated;
```

Izar's real policies, schema and fraud checks aren't published here, since
they'd show an attacker exactly what to work around.

## 4. CI

`.github/workflows/security.yml` scans the whole tree and runs the tests on
every push and pull request. The pre-commit hook can be skipped with
`--no-verify`; CI can't.

## Running it

```bash
npm test                            # run the tests
node tools/scan-secrets.mjs --all   # scan the working tree
```

Requires Node 20+. No other dependencies.

---

**Mark Whipstock** · [izarflags.com](https://izarflags.com) ·
[linkedin.com/in/mark-whipstock](https://linkedin.com/in/mark-whipstock)
