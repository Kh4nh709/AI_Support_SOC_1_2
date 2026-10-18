// The rules the users page (P11-T12) is built on, kept away from the DOM so a test can say each one in a line:
// which state an account is in, what the search matches, how long a password is, what a failed write means.
// Nothing here reads the clock or the network.
import { ADMIN_LIMITS, type AdminError, type AdminReason, type UserRow } from "../../api/admin";
import { S, adminReasonText } from "../../strings";

export type AccountState = "active" | "locked" | "inactive";

/**
 * The state of an account at `nowMs`. An inactive account is inactive, locked or not: reactivating it comes
 * first. A lock is on while `locked_until` is ahead of the clock; the server keeps the stamp after it passes,
 * so a stamp in the past is no lock, and a stamp that cannot be read is none either (the login decides).
 */
export function accountState(user: UserRow, nowMs: number): AccountState {
  if (!user.is_active) return "inactive";
  if (user.locked_until !== null) {
    const until = Date.parse(user.locked_until);
    if (!Number.isNaN(until) && until > nowMs) return "locked";
  }
  return "active";
}

/** The search of the page: a part of the username or of the display name, in any case. The text is not a pattern. */
export function matchesSearch(user: UserRow, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (needle === "") return true;
  return (
    user.username.toLowerCase().includes(needle) ||
    (user.display_name ?? "").toLowerCase().includes(needle)
  );
}

/** The length of a text in characters (code points), which is how the server counts: `len()` of a Python str. */
export function codePoints(text: string): number {
  return Array.from(text).length;
}

export type PasswordProblem =
  | { reason: "empty" }
  | { reason: "too_short"; have: number; min: number }
  | { reason: "too_long"; max: number };

/** What is wrong with a password before it is posted, by the server's own limits (`ADMIN_LIMITS`), or null. Not trimmed. */
export function passwordProblem(password: string): PasswordProblem | null {
  if (password === "") return { reason: "empty" };
  const have = codePoints(password);
  if (have < ADMIN_LIMITS.passwordMin) {
    return { reason: "too_short", have, min: ADMIN_LIMITS.passwordMin };
  }
  if (have > ADMIN_LIMITS.passwordMax) return { reason: "too_long", max: ADMIN_LIMITS.passwordMax };
  return null;
}

/** The words for a password problem, as the canvas has them ("Cần tối thiểu 12 ký tự, đang có 8"). */
export function passwordProblemText(problem: PasswordProblem): string {
  switch (problem.reason) {
    case "empty":
      return S.admin.reason.empty;
    case "too_short":
      return S.admin.usersPage.password.short(problem.min, problem.have);
    case "too_long":
      return S.admin.bounds.tooLong(problem.max);
  }
}

// --- the create form ------------------------------------------------------------------------------------------

export type NewUserValues = {
  username: string;
  displayName: string;
  role: UserRow["role"] | null;
  password: string;
  repeat: string;
};

/** The fields of the create form that can carry an error, by the name the server uses (`repeat` is the form's own). */
export type NewUserField = "username" | "display_name" | "role" | "password" | "repeat";
export type NewUserErrors = Partial<Record<NewUserField, string>>;

/** The order the fields are in on the page, which is the order the first error is focused in. */
export const NEW_USER_FIELDS: readonly NewUserField[] = [
  "username",
  "display_name",
  "role",
  "password",
  "repeat",
];

export function isNewUserField(name: string): name is NewUserField {
  return (NEW_USER_FIELDS as readonly string[]).includes(name);
}

/**
 * What the create form can check before it posts, mirroring the server's checks that do not depend on the
 * database: the username pattern and the two reserved names, an empty or over-long display name, a role
 * chosen, the password's length, and the repeat. It does not guess at which characters a display name may
 * hold (the server's Unicode tables decide that: a 422 `invalid` shows at the field).
 */
export function checkNewUser(values: NewUserValues): NewUserErrors {
  const errors: NewUserErrors = {};
  if (values.username === "") errors.username = S.admin.reason.empty;
  else if (!ADMIN_LIMITS.username.test(values.username)) {
    errors.username = S.admin.usersPage.create.usernameInvalid;
  } else if ((ADMIN_LIMITS.reservedUsernames as readonly string[]).includes(values.username)) {
    errors.username = S.admin.reason.reserved;
  }
  const name = values.displayName.trim();
  if (name === "") errors.display_name = S.admin.reason.empty;
  else if (codePoints(name) > ADMIN_LIMITS.displayNameMax) {
    errors.display_name = S.admin.bounds.tooLong(ADMIN_LIMITS.displayNameMax);
  }
  if (values.role === null) errors.role = S.admin.usersPage.create.roleMissing;
  const problem = passwordProblem(values.password);
  if (problem !== null) errors.password = passwordProblemText(problem);
  if (values.repeat !== values.password) errors.repeat = S.admin.usersPage.password.mismatch;
  return errors;
}

// --- what a failed write means ----------------------------------------------------------------------------------

export type Failure = {
  /** The words for the admin. */
  text: string;
  /** The server refused, and pressing the button again cannot change that: a dialog keeps only "Đóng". */
  refusal: boolean;
  /** The field the answer is about (a 422 with a `field`, or a 409 `username_taken`), or null. */
  field: string | null;
  /** The list on screen may be out of date (the account is gone, or its role is not what we showed): read it again. */
  reload: boolean;
};

/** The refusals no retry can turn into an answer of yes. */
const REFUSALS: readonly AdminReason[] = [
  "last_active_admin",
  "self_change",
  "forbidden",
  "not_found",
];
/** The refusals that say the list shown is not the truth any more. */
const STALE: readonly AdminReason[] = ["last_active_admin", "not_found"];

/** Plainer words than "Giá trị không hợp lệ" for the three `invalid` the user routes answer with. */
function fieldText(field: string, error: Extract<AdminError, { kind: "field" }>): string {
  if (error.reason === "invalid") {
    if (field === "username") return S.admin.usersPage.create.usernameInvalid;
    if (field === "display_name") return S.admin.usersPage.create.displayNameInvalid;
    if (field === "password") return S.admin.usersPage.password.invalid;
  }
  return adminReasonText(error);
}

/**
 * Reads a failed write of the user routes (`adminErrorOf`'s answer) into what the page shows and does.
 * Every answer has words: the server's reason in Vietnamese where it gave one, and for an answer with no
 * reason (a 5xx, a network failure) the plain "could not save" sentences.
 */
export function failureOf(error: AdminError): Failure {
  switch (error.kind) {
    case "reason":
      return {
        text: adminReasonText(error),
        refusal: REFUSALS.includes(error.reason),
        field: error.reason === "username_taken" ? "username" : null,
        reload: STALE.includes(error.reason),
      };
    case "field":
      return {
        text: fieldText(error.field, error),
        refusal: false,
        field: error.field,
        reload: false,
      };
    case "message":
      return { text: error.message, refusal: false, field: null, reload: false };
    case "messages":
      return { text: error.messages.join(" "), refusal: false, field: null, reload: false };
    case "other":
      return {
        text:
          error.status === 0
            ? S.admin.usersPage.writeFailed.network
            : S.admin.usersPage.writeFailed.server,
        refusal: false,
        field: null,
        reload: false,
      };
  }
}
