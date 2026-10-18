// Who is labelling (P11-T16). `GET /api/admin/labels/next?labeler=` wants the caller's own user id, and the
// session holds a token, a role and a name but no id. The blind page may make no request but the three label
// routes (plan Review Focus 5), so it cannot ask `GET /api/auth/me`; it reads the id from the token it already
// holds: the `sub` claim of the JWT the login issued (`infra/auth.py`, `_TOKEN_CLAIMS = sub, role, iat, exp`).
//
// This reads the payload; it checks nothing. The server verifies the signature on every request and answers
// 403 to a `labeler` that is not the token's user (`_bind` of web/routers/labels.py), so a wrong reading is
// refused, never obeyed, and one person can never draw another's order.

/** The `sub` of the token's payload, or null when the token has none that can be read. Never throws. */
export function labelerIdOf(token: string): string | null {
  const payload = token.split(".")[1];
  if (payload === undefined || payload === "") return null;
  try {
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const claims: unknown = JSON.parse(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "=")));
    if (typeof claims !== "object" || claims === null) return null;
    const sub = (claims as { sub?: unknown }).sub;
    return typeof sub === "string" && sub !== "" ? sub : null;
  } catch {
    return null; // not base64, not JSON
  }
}
