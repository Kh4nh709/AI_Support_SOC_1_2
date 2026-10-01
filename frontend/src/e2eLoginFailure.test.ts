// The Playwright fixtures cannot run under Vitest (they need the scratch stack), so what they do when a login
// fails is a small module of its own (e2e/loginFailure.ts), tested here, and the fixtures' use of it is pinned
// by reading the source. A failing test keeps a snapshot of the page and a screenshot: the password field must
// be empty by then (P10-T12 parked item, P10-T17).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { clearingOnFailure, type Clearable } from "../e2e/loginFailure";

function field(fill: Clearable["fill"] = () => Promise.resolve()) {
  const spy = vi.fn(fill);
  return { fill: spy } satisfies Clearable;
}

describe("clearingOnFailure", () => {
  it("returns what the step returns and leaves the field alone when the step succeeds", async () => {
    const password = field();
    await expect(clearingOnFailure(password, () => Promise.resolve("home"))).resolves.toBe("home");
    expect(password.fill).not.toHaveBeenCalled();
  });

  it("empties the field and then rethrows the very error of the step", async () => {
    const password = field();
    const failure = new Error("expected /queue");
    await expect(clearingOnFailure(password, () => Promise.reject(failure))).rejects.toBe(failure);
    expect(password.fill).toHaveBeenCalledTimes(1);
    expect(password.fill.mock.calls[0]?.[0]).toBe("");
  });

  it("empties it before the failure reaches the test, not after", async () => {
    let emptied = false;
    const password = field(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      emptied = true;
    });
    const settled = clearingOnFailure(password, () => Promise.reject(new Error("no home")));
    await expect(settled).rejects.toThrow("no home");
    expect(emptied).toBe(true);
  });

  it("does not wait on a field that is gone: a short timeout, and the step's error is the one thrown", async () => {
    const password = field(() => Promise.reject(new Error("the page was closed")));
    const failure = new Error("expected /queue");
    await expect(clearingOnFailure(password, () => Promise.reject(failure))).rejects.toBe(failure);
    const options = password.fill.mock.calls[0]?.[1];
    expect(options?.timeout).toBeGreaterThan(0);
    expect(options?.timeout).toBeLessThanOrEqual(5000);
  });
});

describe("the fixtures' logins", () => {
  const source = readFileSync(join(__dirname, "..", "e2e", "fixtures.ts"), "utf8");
  const bodyOf = (name: string): string => {
    const start = source.indexOf(`export async function ${name}(`);
    expect(start, `${name} is exported`).toBeGreaterThanOrEqual(0);
    const next = source.indexOf("\nexport ", start + 1);
    return source.slice(start, next === -1 ? undefined : next);
  };

  it.each(["loginAs", "signIn"])("%s empties the password field when it fails", (name) => {
    expect(source).toMatch(/import \{[^}]*\bclearingOnFailure\b[^}]*\} from "\.\/loginFailure"/);
    expect(bodyOf(name)).toMatch(/clearingOnFailure\(\s*page\.getByLabel\(S\.login\.password\)/);
  });
});
