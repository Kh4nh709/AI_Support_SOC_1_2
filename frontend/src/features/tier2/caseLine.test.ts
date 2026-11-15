// src/features/tier2/caseLine.test.ts — the line at the right of the Tier 2 panel's heading (DEC-221): the case, its
// clusters and the agents they came from, as the approved mock-up has it ("Case 214 · 4 alert · Windows_Endpoint").
import type { CaseDetail } from "../../api/tier2";
import { caseLineOf } from "./caseLine";

const CASE = "0b30b853-1c2d-4e5f-8a9b-0c1d2e3f4a5b";
const head = (agent: string | null) => ({ agent_name: agent }) as CaseDetail["heads"][number];
const detail = (heads: CaseDetail["heads"]) => ({ case_id: CASE, heads });

it("says the first eight characters of the case, the clusters and the agents", () => {
  expect(caseLineOf(detail([head("lab-win-02"), head("lab-ubuntu-01"), head("lab-win-02")]))).toBe(
    "Case 0b30b853 · 3 cụm · lab-win-02, lab-ubuntu-01",
  );
});

it("says one agent once however many clusters came from it", () => {
  expect(caseLineOf(detail([head("lab-win-02"), head("lab-win-02")]))).toBe(
    "Case 0b30b853 · 2 cụm · lab-win-02",
  );
});

it("leaves the agents out when no cluster names one", () => {
  expect(caseLineOf(detail([head(null), head("")]))).toBe("Case 0b30b853 · 2 cụm");
  expect(caseLineOf(detail([]))).toBe("Case 0b30b853 · 0 cụm");
});
