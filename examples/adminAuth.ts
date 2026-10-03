// MFA step-up checks for sensitive server actions.
//
// Callers have already verified the Supabase JWT with getUser(token). These
// helpers check the session's assurance level, so a stolen password alone
// (aal1) can't publish, take down listings, or move money.
import type { User } from '@supabase/supabase-js';

/** Reads the aal claim from the bearer token. The signature is verified
 *  upstream; anything that fails to parse counts as aal1. */
export function tokenAal(request: Request): 'aal1' | 'aal2' {
  try {
    const auth = request.headers.get('Authorization') ?? '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return payload.aal === 'aal2' ? 'aal2' : 'aal1';
  } catch {
    return 'aal1';
  }
}

/** Gate for admin-only actions. Requires aal2 unconditionally rather than
 *  checking whether the account has a factor enrolled, so it can't fail open.
 *  Returns a 403 response, or null to continue. */
export function requireAal2(request: Request): Response | null {
  if (tokenAal(request) === 'aal2') return null;
  return new Response(JSON.stringify({
    error: 'This action needs two-factor: sign out, sign back in with your authenticator code, and try again.',
  }), { status: 403, headers: { 'Content-Type': 'application/json' } });
}

function hasVerifiedFactor(user: User): boolean {
  return ((user as { factors?: Array<{ status?: string }> }).factors ?? [])
    .some((f) => f.status === 'verified');
}

/** Softer gate for regular users: if the account has a verified factor, the
 *  session must be aal2. Accounts without 2FA pass.
 *
 *  This trusts the factors list from the auth provider. If that list were ever
 *  missing for a 2FA account, the request would get through, which is why
 *  admin actions use requireAal2 instead. */
export function mfaStepUp(request: Request, user: User): Response | null {
  if (hasVerifiedFactor(user) && tokenAal(request) !== 'aal2') {
    return new Response(JSON.stringify({
      error: 'This account has two-factor enabled: sign out, sign back in with your authenticator code, and try again.',
    }), { status: 403, headers: { 'Content-Type': 'application/json' } });
  }
  return null;
}
