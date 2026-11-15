// The line at the right of the Tier 2 panel's heading (DEC-221), as the approved mock-up has it ("Case 214 · 4 alert ·
// Windows_Endpoint"): the case, how many clusters it holds and the agents they came from. The page that knows the case
// builds it and hands it to the ② column, which knows only the case's id.
import type { CaseDetail } from "../../api/tier2";
import { S } from "../../strings";

/** The case id is a UUID: its first eight characters name the case on the line, as the list's first column does. */
const SHORT_ID = 8;

export function caseLineOf(data: Pick<CaseDetail, "case_id" | "heads">): string {
  const agents = new Set<string>();
  for (const head of data.heads) {
    if (typeof head.agent_name === "string" && head.agent_name.trim() !== "") {
      agents.add(head.agent_name);
    }
  }
  return S.ai2.caseLine(data.case_id.slice(0, SHORT_ID), data.heads.length, [...agents]);
}
