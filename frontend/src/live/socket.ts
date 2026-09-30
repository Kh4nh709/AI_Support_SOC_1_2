// The client of /api/ws (P10-T05 server, DEC-162). The protocol, in the order of the wire:
//   1. the client opens `ws(s)://<page host>/api/ws` (no query: the token is NEVER in the URL);
//   2. its first frame is {"type":"auth","token":"<jwt>"}, within the server's 5 s;
//   3. the server answers {"type":"ready"}, then {"type":"alerts.changed","ids":[...]} or {..."many":true};
//   4. close 4401 is a 401 (bad or expired token, or a logout), 4403 a role that may not listen, 1011 an
//      outage of the server.
// The messages carry ids only (the blind arm): what changed is fetched again through the API, as the caller
// sees fit. This file knows the wire and nothing about queries or the page.

export type LiveStatus = "live" | "offline";
/** The ids a message names, or "many" when the server folded a burst into one message. */
export type LiveChange = string[] | "many";

export type LiveOptions = {
  /** The token of the session, read each time a socket opens: a reconnect sends the current one. */
  token: () => string | null;
  onChange: (change: LiveChange) => void;
  onStatus: (status: LiveStatus) => void;
  /** The server closed with 4401. Gets the token that was sent, so the owner can end that session only. */
  onUnauthorized?: (sentToken: string) => void;
  /** Where to connect; the page's own host by default. */
  url?: string;
};

/** The first wait after a drop; each further failure doubles it, up to `BACKOFF_MAX_MS`. */
export const BACKOFF_BASE_MS = 1_000;
export const BACKOFF_MAX_MS = 30_000;
/**
 * A socket that has been live for this long was a good one, and a drop after it starts the backoff over.
 * Resetting on `ready` alone would let a server that closes right after ready be called about once a second.
 */
export const STABLE_LIVE_MS = 10_000;

const CLOSE_UNAUTHORIZED = 4401;
const CLOSE_FORBIDDEN = 4403;
const CLOSE_NORMAL = 1000;

/** `/api/ws` on the host of the page, wss over https. No query and no credentials in it, ever. */
export function liveUrl(where: Pick<Location, "protocol" | "host"> = window.location): string {
  return `${where.protocol === "https:" ? "wss:" : "ws:"}//${where.host}/api/ws`;
}

/** What a text frame says, or null for anything this client does not act on. */
function parseFrame(data: unknown): { type: string; body: Record<string, unknown> } | null {
  if (typeof data !== "string") return null;
  let body: unknown;
  try {
    body = JSON.parse(data);
  } catch {
    return null;
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const record = body as Record<string, unknown>;
  return typeof record.type === "string" ? { type: record.type, body: record } : null;
}

/** The change a frame names: its string ids, "many", or null when it names nothing usable. */
function changeOf(body: Record<string, unknown>): LiveChange | null {
  if (body.many === true) return "many";
  if (!Array.isArray(body.ids)) return null;
  const ids = body.ids.filter((id): id is string => typeof id === "string");
  return ids.length > 0 ? ids : null;
}

/**
 * Keeps one socket to /api/ws open for as long as it is not disconnected. A drop is `offline` and a new
 * socket follows after a backoff, except for 4401 (the session is over) and 4403 (this role may not listen),
 * which retrying cannot change. Returns the function that stops it for good.
 */
export function connectLive(opts: LiveOptions): () => void {
  let stopped = false;
  let socket: WebSocket | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let failures = 0;
  let status: LiveStatus | null = null;

  const report = (next: LiveStatus) => {
    if (status === next) return;
    status = next;
    opts.onStatus(next);
  };

  const scheduleReconnect = () => {
    const wait = Math.min(BACKOFF_BASE_MS * 2 ** failures, BACKOFF_MAX_MS);
    failures += 1;
    timer = setTimeout(connect, wait);
  };

  function connect(): void {
    timer = undefined;
    if (stopped) return;
    let ws: WebSocket;
    try {
      ws = new WebSocket(opts.url ?? liveUrl());
    } catch {
      report("offline");
      scheduleReconnect();
      return;
    }
    socket = ws;
    let sentToken: string | null = null;
    let ready = false;
    let readyAt = 0;
    const current = () => !stopped && socket === ws;

    ws.addEventListener("open", () => {
      if (!current()) return;
      const token = opts.token();
      if (token === null) {
        // The session is gone: there is nothing to say and nobody to say it as. A new session connects anew.
        stopped = true;
        report("offline");
        ws.close(CLOSE_NORMAL);
        return;
      }
      sentToken = token;
      ws.send(JSON.stringify({ type: "auth", token }));
    });

    ws.addEventListener("message", (event: MessageEvent) => {
      if (!current()) return;
      const frame = parseFrame(event.data);
      if (frame === null) return;
      if (frame.type === "ready") {
        ready = true;
        readyAt = Date.now(); // `failures` is not reset here: see STABLE_LIVE_MS
        report("live");
      } else if (frame.type === "alerts.changed" && ready) {
        const change = changeOf(frame.body);
        if (change !== null) opts.onChange(change);
      }
    });

    ws.addEventListener("close", (event: CloseEvent) => {
      if (!current()) return;
      socket = null;
      report("offline");
      // Only a socket that stayed live for a while was a good one; the backoff starts over after it.
      if (ready && Date.now() - readyAt >= STABLE_LIVE_MS) failures = 0;
      if (event.code === CLOSE_UNAUTHORIZED) {
        stopped = true;
        if (sentToken !== null) opts.onUnauthorized?.(sentToken);
      } else if (event.code === CLOSE_FORBIDDEN) {
        stopped = true;
      } else {
        scheduleReconnect();
      }
    });
  }

  connect();

  return () => {
    stopped = true;
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
    const ws = socket;
    socket = null;
    ws?.close(CLOSE_NORMAL);
  };
}
