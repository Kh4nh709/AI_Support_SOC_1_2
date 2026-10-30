// Whether ① and the person who decided agree, worded the way the pilot report counts it (P10-T06,
// eval/ops_export.py: `Q_PILOT_AGREEMENT` over `_PILOT_VERDICT`). The console must not say "khớp" for a pair
// the report calls a disagreement, so the mapping is that file's and is not this file's to improve:
//   - ① `escalate` agrees with a human escalation (status `escalated_tier2`);
//   - ① `false_positive` agrees with a human `false_positive` (status `closed_fp`);
//   - any other pair of a ① verdict and a human decision disagrees, a human `benign` (status `closed_benign`)
//     after ① `false_positive` included: ① has no `benign` verdict;
//   - ① `needs_review`, no ① result, and an action that is none of the three are no verdict (the report
//     leaves them out of the denominator): nothing is compared.
// A decision that is not a Tier 1 person's (`auto_closed`, and a `closed_confirmed` with no case, which is
// Tier 2's conclusion) is not in the report at all, so it has no comparison: `null`. An alert with a case was
// escalated by Tier 1 whatever its status is now (see `humanDecisionOf`), and is compared as an escalation.
// An `archived` alert (DEC-212, the old queue set aside without review) is not a decision at all: `null`.

export type Agreement = "agree" | "disagree" | "no_verdict";

/** What the human did, in the report's words. */
export type HumanDecision = "escalated" | "false_positive" | "benign";

/** `alerts.case_id` as the view carries it: absent, null, or the case's id. */
export type CaseRef = number | string | null | undefined;

/** The human decision behind a status, in the report's words; a status that is not a Tier 1 decision has none. */
const HUMAN: Readonly<Record<string, HumanDecision>> = {
  escalated_tier2: "escalated",
  closed_fp: "false_positive",
  closed_benign: "benign",
};

/**
 * What the pilot report counts as the human decision on this alert. The report reads it from the audit events,
 * not from the status: a Tier 2 conclusion rewrites the status of an alert Tier 1 escalated (`concluded_fp` →
 * `closed_fp`, `concluded_policy_violation` → `closed_benign`, `confirmed_incident` → `closed_confirmed`,
 * transitions.py `_CONCLUSION_TO_ALERT_STATUS`), and the report still counts the `tier1.escalated` event. Only an
 * escalation writes `alerts.case_id` (transitions.py, A11), so a case id says the human decision was an
 * escalation, whatever the status is now. With no case, the status is the decision.
 */
export function humanDecisionOf(status: string, caseId: CaseRef): HumanDecision | null {
  // DEC-212: an archived alert (the old queue, set aside without review) is nobody's decision, with a case or
  // without one - the case it may carry was archived with it. A person's earlier escalation of it stays in the
  // audit log (`tier1.escalated`); this function says what the alert is now.
  if (status === "archived") return null;
  if (caseId !== null && caseId !== undefined) return "escalated";
  return HUMAN[status] ?? null;
}

export function agreementOf(
  status: string,
  action: string | null,
  caseId: CaseRef,
): Agreement | null {
  const human = humanDecisionOf(status, caseId);
  if (human === null) return null;
  if (action !== "escalate" && action !== "false_positive") return "no_verdict";
  const agrees =
    (action === "escalate" && human === "escalated") ||
    (action === "false_positive" && human === "false_positive");
  return agrees ? "agree" : "disagree";
}
