// The new-ticket signal of the SOAR page (spec section 7): a short tone made with WebAudio (an oscillator, no audio
// file, so nothing is fetched and the CSP stays as it is) and a browser Notification whose words are `strings.ts`'s and
// whose only datum is the number of open tickets. The switch that turns it on lives on the page and is kept in
// `storage.ts`. Every call is inside try/catch and looks the browser API up when it is called: a browser with no
// AudioContext or no Notification, a denied permission, a device that cannot play, never break the header that calls this.
import { S } from "../../strings";
import { readSignalOn, writeSignalOn } from "./storage";

export type NotificationState = "granted" | "denied" | "default" | "absent";

type AudioCtor = new () => AudioContext;
type NotificationCtor = {
  new (title: string, options?: NotificationOptions): unknown;
  permission: string;
  requestPermission: () => unknown;
};

const audioCtor = (): AudioCtor | null => {
  const scope = globalThis as unknown as {
    AudioContext?: AudioCtor;
    webkitAudioContext?: AudioCtor;
  };
  return scope.AudioContext ?? scope.webkitAudioContext ?? null;
};

const notificationCtor = (): NotificationCtor | null => {
  const found = (globalThis as unknown as { Notification?: NotificationCtor }).Notification;
  return typeof found === "function" ? found : null;
};

/** What the browser lets this page show: its permission, or `absent` when it has no Notification API. */
export function notificationState(): NotificationState {
  const permission = notificationCtor()?.permission;
  if (permission === undefined) return "absent";
  return permission === "granted" || permission === "denied" ? permission : "default";
}

/**
 * Whether the newest ticket is newer than the one last seen. Instants are compared, not text. A first ticket after
 * none is forward; a missing or unreadable newest one never is.
 */
export function movedForward(prev: string | null, next: string | null): boolean {
  if (next === null) return false;
  const now = Date.parse(next);
  if (Number.isNaN(now)) return false;
  if (prev === null) return true;
  const before = Date.parse(prev);
  return Number.isNaN(before) || now > before;
}

// One AudioContext for the whole signal. It is made, or woken, on the click that turns the signal on (a user gesture: the one
// moment a browser lets a page start audio), reused for every tone, and let go when the switch is turned off or the header
// that owns the signal goes (`closeSignalAudio`, the end of the session). It is never made while the switch is off, and a
// failure to make or wake it is swallowed: the notification still goes.
let context: AudioContext | null = null;

/** The context of the signal: the one made already (woken if the browser suspended it), or a new one; null when it cannot be. */
function audio(): AudioContext | null {
  try {
    if (context === null || context.state === "closed") {
      const Context = audioCtor();
      if (Context === null) return null;
      context = new Context();
    }
    if (context.state === "suspended")
      void Promise.resolve(context.resume()).catch(() => undefined);
    return context;
  } catch {
    context = null;
    return null;
  }
}

/** Lets the audio context go, once; a later tone makes a new one if the switch is still on. */
export function closeSignalAudio(): void {
  const gone = context;
  context = null;
  if (gone === null || gone.state === "closed") return;
  try {
    void Promise.resolve(gone.close()).catch(() => undefined);
  } catch {
    // already gone
  }
}

/** About a third of a second of a soft A5: short, and not a siren. */
function playTone(): void {
  try {
    const shared = audio();
    if (shared === null) return;
    const oscillator = shared.createOscillator();
    const gain = shared.createGain();
    oscillator.type = "sine";
    oscillator.frequency.value = 880;
    const t = shared.currentTime;
    gain.gain.setValueAtTime(0.0001, t);
    gain.gain.exponentialRampToValueAtTime(0.2, t + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.35);
    oscillator.connect(gain);
    gain.connect(shared.destination);
    oscillator.start();
    oscillator.stop(t + 0.4);
  } catch {
    // no device, or the browser refused to start audio: the notification still goes
  }
}

function showNotification(open: number): void {
  try {
    const Notify = notificationCtor();
    if (Notify === null || Notify.permission !== "granted") return;
    const shown = new Notify(S.soar.signal.notification.title, {
      body: S.soar.signal.notification.body(open),
      tag: "soar-review",
    });
    void shown;
  } catch {
    // some browsers refuse `new Notification` outside a service worker: the tone has played
  }
}

/** A new ticket has arrived and `open` are open: the tone and the notification, when the switch is on. */
export function signalNewTicket(open: number): void {
  if (!readSignalOn()) return;
  playTone();
  showNotification(open);
}

/**
 * The switch on: kept at once, and permission asked once, here, on the click (never at load, never again once decided).
 * The promise settles when the browser has answered, so the page can read the permission again.
 */
export async function turnSignalOn(): Promise<void> {
  writeSignalOn(true);
  // on the click: the one moment a browser lets this page start audio
  audio();
  try {
    const Notify = notificationCtor();
    if (Notify === null || notificationState() !== "default") return;
    await Promise.resolve(Notify.requestPermission());
  } catch {
    // the tone works without it
  }
}

export function turnSignalOff(): void {
  writeSignalOn(false);
  closeSignalAudio();
}
