// src/features/soar/signal.test.ts — the new-ticket signal: a short tone (WebAudio, no file) and a browser Notification.
// `AudioContext` and `Notification` are faked; jsdom has neither. The switch is per tab (the session store of the tab); a tab
// that has not chosen signals when the browser already holds the notification permission. The tone needs a gesture.
import { afterEach, beforeEach, vi } from "vitest";
import { S } from "../../strings";
import {
  closeSignalAudio,
  movedForward,
  notificationState,
  primeAudio,
  signalEnabled,
  signalNewTicket,
  turnSignalOff,
  turnSignalOn,
} from "./signal";
import { SIGNAL_KEY, readSignalChoice } from "./storage";

class FakeAudioContext {
  static made: FakeAudioContext[] = [];
  static fail = false;
  state = "running";
  currentTime = 0;
  destination = {};
  oscillators: {
    type: string;
    frequency: { value: number };
    connect: () => void;
    start: ReturnType<typeof vi.fn>;
    stop: ReturnType<typeof vi.fn>;
    onended: (() => void) | null;
  }[] = [];
  resume = vi.fn(async () => {});
  close = vi.fn(async () => {});
  constructor() {
    if (FakeAudioContext.fail) throw new Error("no audio device");
    FakeAudioContext.made.push(this);
  }
  createOscillator() {
    const oscillator = {
      type: "",
      frequency: { value: 0 },
      connect: vi.fn(),
      start: vi.fn(),
      stop: vi.fn(),
      onended: null,
    };
    this.oscillators.push(oscillator);
    return oscillator;
  }
  createGain() {
    return {
      gain: { setValueAtTime: vi.fn(), exponentialRampToValueAtTime: vi.fn() },
      connect: vi.fn(),
    };
  }
}

class FakeNotification {
  static permission = "granted";
  static shown: { title: string; options: NotificationOptions | undefined }[] = [];
  static requestPermission = vi.fn(async () => "granted");
  constructor(title: string, options?: NotificationOptions) {
    FakeNotification.shown.push({ title, options });
  }
}

const tones = () => FakeAudioContext.made.flatMap((c) => c.oscillators);

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
  FakeAudioContext.made = [];
  FakeAudioContext.fail = false;
  FakeNotification.shown = [];
  FakeNotification.permission = "granted";
  FakeNotification.requestPermission = vi.fn(async () => "granted");
  vi.stubGlobal("AudioContext", FakeAudioContext);
  vi.stubGlobal("Notification", FakeNotification);
});
afterEach(() => {
  // the one audio context of the module belongs to no test: let it go before the next one stubs its own
  closeSignalAudio();
  vi.unstubAllGlobals();
  // nothing was ever written to the store that outlives the tab
  expect(localStorage.length).toBe(0);
});

describe("movedForward", () => {
  it("is true only when the newest ticket is newer than the one last seen", () => {
    expect(movedForward("2026-11-16T01:00:00+00:00", "2026-11-16T01:00:01+00:00")).toBe(true);
    expect(movedForward("2026-11-16T01:00:00+00:00", "2026-11-16T01:00:00+00:00")).toBe(false);
    expect(movedForward("2026-11-16T01:00:00+00:00", "2026-11-16T00:59:00+00:00")).toBe(false);
  });

  it("compares instants, not text: +07 and +00 forms of one moment are the same", () => {
    expect(movedForward("2026-11-16T08:00:00+07:00", "2026-11-16T01:00:00+00:00")).toBe(false);
    expect(movedForward("2026-11-16T08:00:00+07:00", "2026-11-16T01:00:01+00:00")).toBe(true);
  });

  it("counts a first ticket after none as forward, and nothing after a ticket as backward", () => {
    expect(movedForward(null, "2026-11-16T01:00:00+00:00")).toBe(true);
    expect(movedForward("2026-11-16T01:00:00+00:00", null)).toBe(false);
    expect(movedForward(null, null)).toBe(false);
  });

  it("says no for a time it cannot read", () => {
    expect(movedForward("2026-11-16T01:00:00+00:00", "later")).toBe(false);
    expect(movedForward("earlier", "2026-11-16T01:00:00+00:00")).toBe(true);
  });
});

// A tab that has not chosen: the signal is ON when the browser already holds the notification permission (the browser
// remembers that grant itself, which is the "ask once"), OFF otherwise. A choice made in the tab wins over it.
describe("the default of a tab that has not chosen", () => {
  it.each([
    ["granted", true],
    ["default", false],
    ["denied", false],
  ] as const)("with the permission %s the signal is %s", (permission, on) => {
    FakeNotification.permission = permission;
    expect(readSignalChoice()).toBeNull();
    expect(signalEnabled()).toBe(on);
  });

  it("is off when the browser has no Notification API", () => {
    vi.stubGlobal("Notification", undefined);
    expect(signalEnabled()).toBe(false);
    expect(() => signalNewTicket(1)).not.toThrow();
    expect(FakeAudioContext.made).toEqual([]);
  });

  it("when on by default, shows the notification ALONE: the tone needs a gesture, and no context is made without one", () => {
    signalNewTicket(2);
    expect(FakeNotification.shown).toHaveLength(1);
    expect(FakeNotification.shown[0]?.options?.body).toBe("Có 2 phiếu đang mở");
    expect(FakeAudioContext.made).toEqual([]);
    expect(tones()).toEqual([]);
  });

  it("when off by default (permission not granted), does nothing at all", () => {
    for (const permission of ["default", "denied"]) {
      FakeNotification.permission = permission;
      signalNewTicket(2);
    }
    expect(FakeNotification.shown).toEqual([]);
    expect(FakeAudioContext.made).toEqual([]);
  });

  it("a choice made in the tab wins: off with the permission granted is silent, on with it denied is a tone alone", () => {
    turnSignalOff();
    expect(signalEnabled()).toBe(false);
    signalNewTicket(1);
    expect(FakeNotification.shown).toEqual([]);
    expect(FakeAudioContext.made).toEqual([]);
    FakeNotification.permission = "denied";
    turnSignalOn();
    expect(signalEnabled()).toBe(true);
    signalNewTicket(1);
    expect(FakeNotification.shown).toEqual([]);
    expect(tones()).toHaveLength(1);
  });

  it("keeps the choice for this tab only: 1 and 0 in the session store, and nothing in the store that outlives the tab", () => {
    turnSignalOn();
    expect(sessionStorage.getItem(SIGNAL_KEY)).toBe("1");
    expect(readSignalChoice()).toBe(true);
    turnSignalOff();
    expect(sessionStorage.getItem(SIGNAL_KEY)).toBe("0");
    expect(readSignalChoice()).toBe(false);
    expect(localStorage.length).toBe(0);
  });

  it("a poisoned stored value is no choice, so the default stands", () => {
    sessionStorage.setItem(SIGNAL_KEY, "maybe");
    expect(signalEnabled()).toBe(true);
    FakeNotification.permission = "default";
    expect(signalEnabled()).toBe(false);
  });
});

describe("signalNewTicket", () => {
  it("does nothing while the switch is off: no tone, no notification, and no audio context is ever made", () => {
    turnSignalOff();
    signalNewTicket(2);
    expect(FakeAudioContext.made).toEqual([]);
    expect(FakeNotification.shown).toEqual([]);
  });

  it("plays one short tone and shows one notification, worded by strings.ts and carrying only the count", () => {
    turnSignalOn();
    signalNewTicket(3);
    expect(tones()).toHaveLength(1);
    const [tone] = tones();
    expect(tone?.start).toHaveBeenCalledTimes(1);
    expect(tone?.stop).toHaveBeenCalledTimes(1);
    expect(FakeNotification.shown).toHaveLength(1);
    expect(FakeNotification.shown[0]?.title).toBe(S.soar.signal.notification.title);
    expect(FakeNotification.shown[0]?.options?.body).toBe(S.soar.signal.notification.body(3));
    expect(S.soar.signal.notification.body(3)).toBe("Có 3 phiếu đang mở");
  });

  it("plays the tone alone when permission is denied, and when it was never decided", () => {
    turnSignalOn();
    for (const permission of ["denied", "default"]) {
      FakeNotification.permission = permission;
      FakeNotification.shown = [];
      const before = tones().length;
      signalNewTicket(1);
      expect(tones().length - before, permission).toBe(1);
      expect(FakeNotification.shown, permission).toEqual([]);
    }
  });

  it("plays the tone alone, and does not throw, when the browser has no Notification API", () => {
    vi.stubGlobal("Notification", undefined);
    turnSignalOn();
    expect(() => signalNewTicket(1)).not.toThrow();
    expect(tones()).toHaveLength(1);
  });

  it("shows the notification alone, and does not throw, when there is no AudioContext, or it cannot start", () => {
    vi.stubGlobal("AudioContext", undefined);
    expect(() => turnSignalOn()).not.toThrow();
    expect(() => signalNewTicket(1)).not.toThrow();
    expect(FakeNotification.shown).toHaveLength(1);
    vi.stubGlobal("AudioContext", FakeAudioContext);
    FakeAudioContext.fail = true;
    expect(() => primeAudio()).not.toThrow();
    expect(() => signalNewTicket(1)).not.toThrow();
    expect(FakeNotification.shown).toHaveLength(2);
    expect(FakeAudioContext.made).toEqual([]);
  });

  it("does nothing, and does not throw, with neither API", () => {
    vi.stubGlobal("Notification", undefined);
    vi.stubGlobal("AudioContext", undefined);
    expect(() => turnSignalOn()).not.toThrow();
    expect(() => signalNewTicket(1)).not.toThrow();
  });

  it("goes quiet again at once when the switch is turned off, and lets its audio context go", () => {
    turnSignalOn();
    const context = FakeAudioContext.made[0];
    turnSignalOff();
    expect(context?.close).toHaveBeenCalledTimes(1);
    const before = FakeAudioContext.made.length;
    signalNewTicket(1);
    expect(FakeAudioContext.made).toHaveLength(before);
    expect(FakeNotification.shown).toEqual([]);
  });
});

// One AudioContext for the whole signal, made (or woken) only on a gesture of the person: the click that turns the signal on,
// or `primeAudio()` from a handler the page already has (a press, a dismissal, a search). A tone never makes one: with none, the
// notification goes alone. It is let go when the switch is turned off and when the header that owns the signal goes.
describe("the one audio context", () => {
  it("is made on the click that turns the signal on, and by nothing else", () => {
    expect(FakeAudioContext.made).toEqual([]);
    turnSignalOn();
    expect(FakeAudioContext.made).toHaveLength(1);
  });

  it("is made by a gesture of the page when the signal is on by default, and then the tone joins the notification", () => {
    signalNewTicket(1);
    expect(tones()).toEqual([]);
    primeAudio();
    expect(FakeAudioContext.made).toHaveLength(1);
    signalNewTicket(2);
    expect(tones()).toHaveLength(1);
    expect(FakeNotification.shown).toHaveLength(2);
    // a second gesture makes no second context
    primeAudio();
    expect(FakeAudioContext.made).toHaveLength(1);
  });

  it("is not made by a gesture while the signal is off", () => {
    turnSignalOff();
    primeAudio();
    FakeNotification.permission = "default";
    sessionStorage.clear();
    primeAudio();
    expect(FakeAudioContext.made).toEqual([]);
  });

  it("is reused for every tone: two tones, one context, two oscillators, and it is not closed after a tone", () => {
    turnSignalOn();
    signalNewTicket(1);
    signalNewTicket(2);
    expect(FakeAudioContext.made).toHaveLength(1);
    const [context] = FakeAudioContext.made;
    expect(context?.oscillators).toHaveLength(2);
    context?.oscillators[0]?.onended?.();
    expect(context?.close).not.toHaveBeenCalled();
  });

  it("is woken when the browser kept it suspended: on the click, and again when a tone is due", () => {
    class Suspended extends FakeAudioContext {
      override state = "suspended";
    }
    vi.stubGlobal("AudioContext", Suspended);
    turnSignalOn();
    const [context] = FakeAudioContext.made;
    expect(context?.resume).toHaveBeenCalledTimes(1);
    signalNewTicket(1);
    expect(context?.resume).toHaveBeenCalledTimes(2);
    expect(context?.oscillators).toHaveLength(1);
  });

  it("swallows a failure to wake it, a rejected resume as well as a throw, and still shows the notification", async () => {
    class Stubborn extends FakeAudioContext {
      override state = "suspended";
      override resume = vi.fn(async () => {
        throw new Error("not allowed");
      });
    }
    vi.stubGlobal("AudioContext", Stubborn);
    turnSignalOn();
    expect(() => signalNewTicket(1)).not.toThrow();
    await Promise.resolve();
    expect(FakeNotification.shown).toHaveLength(1);
    class Throwing extends FakeAudioContext {
      override createOscillator(): never {
        throw new Error("no device");
      }
    }
    closeSignalAudio();
    vi.stubGlobal("AudioContext", Throwing);
    turnSignalOn();
    expect(() => signalNewTicket(2)).not.toThrow();
    expect(FakeNotification.shown).toHaveLength(2);
  });

  it("is let go by closeSignalAudio, once, and a later tone makes none: the next gesture makes a new one", () => {
    turnSignalOn();
    const [first] = FakeAudioContext.made;
    closeSignalAudio();
    expect(first?.close).toHaveBeenCalledTimes(1);
    expect(() => closeSignalAudio()).not.toThrow();
    expect(first?.close).toHaveBeenCalledTimes(1);
    signalNewTicket(1);
    expect(FakeAudioContext.made).toHaveLength(1);
    primeAudio();
    expect(FakeAudioContext.made).toHaveLength(2);
    turnSignalOff();
    const after = FakeAudioContext.made.length;
    primeAudio();
    signalNewTicket(1);
    expect(FakeAudioContext.made).toHaveLength(after);
  });

  it("is made again, on the next gesture, if the browser closed it by itself; a tone in between does not make one", () => {
    turnSignalOn();
    const [first] = FakeAudioContext.made;
    if (first !== undefined) first.state = "closed";
    signalNewTicket(1);
    expect(FakeAudioContext.made).toHaveLength(1);
    expect(tones()).toHaveLength(0);
    primeAudio();
    expect(FakeAudioContext.made).toHaveLength(2);
  });
});

describe("the switch", () => {
  it("turning it on keeps the choice and asks for permission once, when it was never decided", () => {
    FakeNotification.permission = "default";
    turnSignalOn();
    expect(readSignalChoice()).toBe(true);
    expect(FakeNotification.requestPermission).toHaveBeenCalledTimes(1);
  });

  it("does not ask again when permission is already granted or denied, nor when turning it off", () => {
    for (const permission of ["granted", "denied"]) {
      FakeNotification.permission = permission;
      turnSignalOn();
    }
    FakeNotification.permission = "default";
    turnSignalOff();
    expect(FakeNotification.requestPermission).not.toHaveBeenCalled();
    expect(readSignalChoice()).toBe(false);
  });

  it("works with no Notification API, and with a permission request that throws or is rejected", async () => {
    vi.stubGlobal("Notification", undefined);
    expect(() => turnSignalOn()).not.toThrow();
    expect(readSignalChoice()).toBe(true);
    FakeNotification.permission = "default";
    FakeNotification.requestPermission = vi.fn(async () => {
      throw new Error("blocked");
    });
    vi.stubGlobal("Notification", FakeNotification);
    expect(() => turnSignalOn()).not.toThrow();
    FakeNotification.requestPermission = vi.fn(() => {
      throw new Error("sync");
    });
    expect(() => turnSignalOn()).not.toThrow();
    await Promise.resolve();
  });

  it("says what the browser lets it show", () => {
    expect(notificationState()).toBe("granted");
    FakeNotification.permission = "denied";
    expect(notificationState()).toBe("denied");
    FakeNotification.permission = "default";
    expect(notificationState()).toBe("default");
    vi.stubGlobal("Notification", undefined);
    expect(notificationState()).toBe("absent");
  });
});
