// How often a page asks again when the live socket cannot say the server changed. These are the live layer's
// numbers: the queue and the alert page both read them from here, so neither imports the other for a constant.

/** With no live socket a page asks again this often (spec §3). */
export const OFFLINE_POLL_MS = 30_000;

/** While ① has not answered (the server's word: pending) the alert page asks again this often. */
export const PENDING_POLL_MS = 10_000;
