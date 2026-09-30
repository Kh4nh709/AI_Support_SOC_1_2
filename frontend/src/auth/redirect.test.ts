// src/auth/redirect.test.ts — where a login lands: the page the visitor was sent away from, if it is ours.
import { landingAfterLogin, roleHome } from "./redirect";

const land = (from: unknown, role: "tier1" | "tier2" | "admin" = "tier1") =>
  landingAfterLogin({ from }, role);

describe("roleHome", () => {
  it("opens tier1 at the queue, and tier2 and admin at the case list", () => {
    expect(roleHome("tier1")).toBe("/queue");
    expect(roleHome("tier2")).toBe("/cases");
    expect(roleHome("admin")).toBe("/cases");
  });
});

describe("landingAfterLogin honours a return path that stays in the app", () => {
  it.each([
    "/queue?band=high",
    "/alerts/12",
    "/cases/3?tab=notes#top",
    "/queue?next=//not-a-host", // a `//` after the path is only text
  ])("returns to %s", (from) => {
    expect(land(from)).toBe(from);
  });

  it("goes to the role home when there is no return path", () => {
    expect(landingAfterLogin(null, "tier2")).toBe("/cases");
    expect(landingAfterLogin(undefined, "tier1")).toBe("/queue");
    expect(landingAfterLogin({}, "admin")).toBe("/cases");
    expect(landingAfterLogin({ forbidden: true }, "tier1")).toBe("/queue");
  });
});

describe("landingAfterLogin refuses a return path that leaves the app", () => {
  // Each is what a link like /login?from=... or a crafted history state could carry.
  it.each<[string, string]>([
    ["a tab before the host", "/\t/evil.example"],
    ["a newline before the host", "/\n/evil.example"],
    ["a carriage return before the host", "/\r/evil.example"],
    ["a backslash for the second slash", "/\\evil.example"],
    ["a protocol-relative URL", "//evil.example"],
    ["a script URL", "javascript:alert(1)"],
    ["an absolute URL", "https://evil.example"],
    ["an absolute http URL", "http://evil.example/queue"],
    ["a data URL", "data:text/html,<b>x</b>"],
    ["no leading slash", "queue"],
    ["the login page itself", "/login"],
    ["the login page with a query", "/login?x=1"],
    ["an empty string", ""],
  ])("sends %s to the role home", (_name, from) => {
    expect(land(from, "tier1")).toBe("/queue");
    expect(land(from, "tier2")).toBe("/cases");
  });

  it.each<[string, unknown]>([
    ["a number", 5],
    ["an object", { path: "/queue" }],
    ["null", null],
  ])("sends %s to the role home", (_name, from) => {
    expect(land(from)).toBe("/queue");
  });

  // The URL parser drops a tab or a newline, and reads a backslash as a slash, so the cases above are
  // caught by the parser as well. These stay inside the origin for the parser and are refused only by
  // the character rules, which is what says those characters have no place in a path of ours.
  it.each<[string, string]>([
    ["a tab inside the path", "/qu\teue"],
    ["a newline inside the path", "/qu\neue"],
    ["a NUL inside the path", "/queue\u0000x"],
    ["a unit separator inside the path", "/queue\u001fx"],
    ["a DEL inside the path", "/queue\u007fx"],
  ])("refuses %s (a control character)", (_name, from) => {
    expect(land(from)).toBe("/queue");
  });

  it("refuses a backslash anywhere in the path", () => {
    expect(land("/queue\\..\\cases")).toBe("/queue");
    expect(land("/alerts/5", "tier2")).toBe("/alerts/5"); // and a plain path is still let through
    expect(land("/queue\\x", "tier2")).toBe("/cases");
  });
});
