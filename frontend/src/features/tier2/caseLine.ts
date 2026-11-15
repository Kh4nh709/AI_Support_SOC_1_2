// The line at the right of the Tier 2 panel's heading (DEC-221), as the approved mock-up has it ("Case 214 · 4 alert ·
// Windows_Endpoint"): the case, how many clusters it holds and the agents they came from. The page that knows the case
// builds it and hands it to the ② column, which knows only the case's id. Every word and joiner is `strings.ts`'s: the
// case (`S.ai2.caseId`), the cluster count the page's own summary uses (`S.case.clusterCount`), and the separators.
import type { CaseDetail } from "../../api/tier2";
import { S } from "../../strings";

/**
 * A case id is a UUID, too long for a line: its first eight characters name the case here. (The case list names a case
 * by its title and links to it by the whole id; nothing else on the page shows a short id.)
 */
const SHORT_ID = 8;

export function caseLineOf(data: Pick<CaseDetail, "case_id" | "heads">): string {
  const agents = new Set<string>();
  for (const head of data.heads) {
    if (typeof head.agent_name === "string" && head.agent_name.trim() !== "") {
      agents.add(head.agent_name);
    }
  }
  const parts = [
    S.ai2.caseId(data.case_id.slice(0, SHORT_ID)),
    S.case.clusterCount(data.heads.length),
    ...(agents.size > 0 ? [[...agents].join(S.analysis.listSeparator)] : []),
  ];
  return parts.join(S.analysis.separator);
}
