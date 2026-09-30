import { canOpenCases, CASE_ROLES } from "./caseAccess";

describe("who may open the case pages", () => {
  it.each([
    ["tier1", false],
    ["tier2", true],
    ["admin", true],
    [null, false],
  ] as const)("says %s: %s", (role, may) => {
    expect(canOpenCases(role)).toBe(may);
  });

  it("is the list the route table shuts the case pages with", () => {
    expect([...CASE_ROLES]).toEqual(["tier2", "admin"]);
  });
});
