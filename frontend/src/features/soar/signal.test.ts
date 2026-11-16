// src/features/soar/signal.test.ts — the new-ticket signal: a short tone (WebAudio, no file) and a browser Notification.
// `AudioContext` and `Notification` are faked; jsdom has neither. The switch is the page's, kept in localStorage.
import { afterEach, beforeEach, vi } from "vitest";
import { S } from "../../strings";
import {
  movedForward,
  notificationState,
  signalNewTicket,
  turnSignalOff,
  turnSignalOn,
} from "./signal";
import { readSignalOn } from "./storage";

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
  localStorage.clear();
  FakeAudioContext.made = [];
  FakeAudioContext.fail = false;
  FakeNotification.shown = [];
  FakeNotification.permission = "granted";
  FakeNotification.requestPermission = vi.fn(async () => "granted");
  vi.stubGlobal("AudioContext", FakeAudioContext);
  vi.stubGlobal("Notification", FakeNotification);
});
afterEach(() => vi.unstubAllGlobals());

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

describe("signalNewTicket", () => {
  it("does nothing while the switch is off: no tone, no notification, no audio context", () => {
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
      FakeAudioContext.made = [];
      signalNewTicket(1);
      expect(tones(), permission).toHaveLength(1);
      expect(FakeNotification.shown, permission).toEqual([]);
    }
  });

  it("plays the tone alone, and does not throw, when the browser has no Notification API", () => {
    vi.stubGlobal("Notification", undefined);
    turnSignalOn();
    expect(() => signalNewTicket(1)).not.toThrow();
    expect(tones()).toHaveLength(1);
  });

  it("shows the notification alone, and does not throw, when there is no AudioContext or it cannot start", () => {
    turnSignalOn();
    vi.stubGlobal("AudioContext", undefined);
    expect(() => signalNewTicket(1)).not.toThrow();
    expect(FakeNotification.shown).toHaveLength(1);
    vi.stubGlobal("AudioContext", FakeAudioContext);
    FakeAudioContext.fail = true;
    expect(() => signalNewTicket(1)).not.toThrow();
    expect(FakeNotification.shown).toHaveLength(2);
  });

  it("does nothing, and does not throw, with neither API", () => {
    turnSignalOn();
    vi.stubGlobal("Notification", undefined);
    vi.stubGlobal("AudioContext", undefined);
    expect(() => signalNewTicket(1)).not.toThrow();
  });

  it("wakes a context the browser kept suspended, and closes it when the tone ends", () => {
    turnSignalOn();
    class Suspended extends FakeAudioContext {
      override state = "suspended";
    }
    vi.stubGlobal("AudioContext", Suspended);
    signalNewTicket(1);
    const context = FakeAudioContext.made[0];
    expect(context?.resume).toHaveBeenCalledTimes(1);
    context?.oscillators[0]?.onended?.();
    expect(context?.close).toHaveBeenCalledTimes(1);
  });

  it("goes quiet again at once when the switch is turned off", () => {
    turnSignalOn();
    turnSignalOff();
    signalNewTicket(1);
    expect(FakeAudioContext.made).toEqual([]);
    expect(FakeNotification.shown).toEqual([]);
  });
});

describe("the switch", () => {
  it("turning it on keeps the choice and asks for permission once, when it was never decided", () => {
    FakeNotification.permission = "default";
    turnSignalOn();
    expect(readSignalOn()).toBe(true);
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
    expect(readSignalOn()).toBe(false);
  });

  it("works with no Notification API, and with a permission request that throws or is rejected", async () => {
    vi.stubGlobal("Notification", undefined);
    expect(() => turnSignalOn()).not.toThrow();
    expect(readSignalOn()).toBe(true);
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
