// The shapes of the auth routes, written by hand against the backend (web/routers/auth.py): the
// backend answers with plain dicts, so there is no generated schema to import.

export const ROLES = ["tier1", "tier2", "admin"] as const;
export type Role = (typeof ROLES)[number];

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

/**
 * The four risk bands, in the order the queue shows them: the codes the queue's `band` filter and its
 * `counts_by_band` speak (P10-T02). A row's own `risk_band` is the Vietnamese label instead (ruling R8).
 */
export const BAND_CODES = ["critical", "high", "medium", "low"] as const;
export type BandCode = (typeof BAND_CODES)[number];

export function isBandCode(value: unknown): value is BandCode {
  return typeof value === "string" && (BAND_CODES as readonly string[]).includes(value);
}

/** `POST /api/auth/login`. */
export type LoginResponse = {
  token: string;
  role: Role;
  /** The user's uuid, as text. */
  user_id: string;
  /** ISO 8601 with an offset. */
  expires_at: string;
};

/** `GET /api/auth/me`. The role comes from the verified token, the name from the users row. */
export type MeResponse = {
  /** The user's uuid, as text. */
  user_id: string;
  username: string;
  display_name: string | null;
  role: Role;
  expires_at: string;
};
