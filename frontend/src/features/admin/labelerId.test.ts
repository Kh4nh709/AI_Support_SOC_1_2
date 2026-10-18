// src/features/admin/labelerId.test.ts — the labeller the blind labelling page asks for (P11-T16). The page may
// make no request but the three label routes, so it cannot ask `/api/auth/me` who the caller is: it reads the
// user id (`sub`) from the session's own token. The server still decides: `labels/next` answers 403 to a
// `labeler` that is not the token's user, so a wrong reading can only be refused, never obeyed.
import { labelerIdOf } from "./labelerId";

const USER_ID = "3f2c1c9e-7a53-4b8e-9c1d-0a4f5e6d7c8b";

/** A JWT segment: base64url of the JSON, no padding. */
const segment = (value: unknown): string =>
  btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const jwt = (claims: unknown): string =>
  `${segment({ alg: "HS256", typ: "JWT" })}.${segment(claims)}.signature`;

describe("labelerIdOf", () => {
  it("reads sub, the user id, from the payload of the token", () => {
    expect(labelerIdOf(jwt({ sub: USER_ID, role: "admin", iat: 1, exp: 2 }))).toBe(USER_ID);
  });

  it.each(["a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg"])(
    "reads a sub of any length, so of any padding: %s",
    (sub) => {
      expect(labelerIdOf(jwt({ sub }))).toBe(sub);
    },
  );

  it("reads the base64url alphabet, - and _ for + and /", () => {
    const token = jwt({ sub: USER_ID, pad: "???>>>~~~" });
    expect(token.split(".")[1]).toMatch(/[-_]/);
    expect(labelerIdOf(token)).toBe(USER_ID);
  });

  it.each([
    ["an empty token", ""],
    ["a token with no dot", "t"],
    ["a token with no payload", "a..c"],
    ["a payload that is not base64", "a.!!!.c"],
    ["a payload that is not JSON", `a.${btoa("not json")}.c`],
    ["a payload that is a list", jwt([USER_ID])],
    ["a payload that is a number", jwt(7)],
    ["a payload that is null", jwt(null)],
    ["a payload with no sub", jwt({ role: "admin" })],
    ["a sub that is a number", jwt({ sub: 7 })],
    ["a sub that is an object", jwt({ sub: { id: USER_ID } })],
    ["an empty sub", jwt({ sub: "" })],
  ])("reads null from %s, and never throws", (_name, token) => {
    expect(labelerIdOf(token)).toBeNull();
  });
});
