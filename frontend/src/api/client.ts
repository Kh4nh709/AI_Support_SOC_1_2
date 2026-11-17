// The one fetch wrapper (spec §3). It uses the base /api, adds `Authorization: Bearer <token>`, parses
// JSON, and reports a 401 to whoever owns the session. Any other error status is thrown as an ApiError
// carrying the server's `detail` unchanged, so the calling component decides what to say (409 a held
// alert, 422 a bad reason, 429 the quota, 503 a timeout).

export class ApiError extends Error {
  readonly status: number;
  /** The server's `detail`, unchanged (an object for a 409); the whole body when it has no `detail`. */
  readonly detail: unknown;
  /** The whole parsed body: a locked login (423) carries `locked_until` beside `detail`. */
  readonly body: unknown;

  constructor(status: number, detail: unknown, body: unknown = detail) {
    super(String(status));
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.body = body;
  }
}

let getToken: () => string | null = () => null;
let unauthorized: () => void = () => {};

/** AuthProvider tells the client where the token is and what to do when the server refuses it. */
export function setTokenSource(get: () => string | null, onUnauthorized: () => void): void {
  getToken = get;
  unauthorized = onUnauthorized;
}

/**
 * The live socket was closed with 4401: the token it authenticated with is not (or no longer) good. The
 * same rule as a 401 answer: it ends the session only when that token is still the current one.
 */
export function reportUnauthorized(sentToken: string): void {
  if (getToken() === sentToken) unauthorized();
}

/** The request both wrappers make: the base, the Bearer header, the JSON body, and the 401 rule (a 401 is thrown here). */
async function send(path: string, init: RequestInit & { json?: unknown }): Promise<Response> {
  const { json, ...rest } = init;
  const headers = new Headers(init.headers);
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let body = init.body;
  if (json !== undefined) {
    headers.set("content-type", "application/json");
    body = JSON.stringify(json);
  }
  const res = await fetch(`/api${path}`, { ...rest, headers, body });
  if (res.status === 401) {
    // Only an answer about the token this request sent says the session ended: a wrong password at the
    // login form has no token, and a request that lost a race with a newer login is about the old one.
    if (token && getToken() === token) unauthorized();
    throw new ApiError(401, null);
  }
  return res;
}

export async function api<T>(
  path: string,
  init: RequestInit & { json?: unknown } = {},
): Promise<T> {
  const res = await send(path, init);
  const data: unknown = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    const detail = (data as { detail?: unknown } | null)?.detail ?? data;
    throw new ApiError(res.status, detail, data);
  }
  return data as T;
}

/**
 * A file from the API as a Blob (the Threat Intel export): the same Bearer header and 401 rule as `api`, which a plain link to the
 * route would not carry. The bytes are kept as they came (`blob()`, not `text()`, so a byte order mark stays); an error status is
 * thrown as the ApiError of `api`, with the server's `detail` read from the JSON body when there is one.
 */
export async function apiBlob(path: string, init: RequestInit = {}): Promise<Blob> {
  const res = await send(path, init);
  if (!res.ok) {
    const data: unknown = await res.json().catch(() => null);
    const detail = (data as { detail?: unknown } | null)?.detail ?? data;
    throw new ApiError(res.status, detail, data);
  }
  return res.blob();
}
