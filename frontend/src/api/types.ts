// The shapes of the auth routes, written by hand against the backend (web/routers/auth.py): the
// backend answers with plain dicts, so there is no generated schema to import.

export const ROLES = ["tier1", "tier2", "admin"] as const;
export type Role = (typeof ROLES)[number];

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

/** `POST /api/auth/login`. */
export type LoginResponse = {
  token: string;
  role: Role;
  user_id: number;
  /** ISO 8601 with an offset. */
  expires_at: string;
};

/** The flat body of a locked login (423): `{"detail": "locked", "locked_until": ...}`. */
export type LockedBody = {
  detail: "locked";
  locked_until?: string;
};

/** `GET /api/auth/me`. The role comes from the verified token, the name from the users row. */
export type MeResponse = {
  user_id: number;
  username: string;
  display_name: string | null;
  role: Role;
  expires_at: string;
};
