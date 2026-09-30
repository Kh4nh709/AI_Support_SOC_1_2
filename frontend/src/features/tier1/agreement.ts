// Whether ① and the person who decided agree, worded the way the pilot report counts it (P10-T06,
// eval/ops_export.py: `Q_PILOT_AGREEMENT` over `_PILOT_VERDICT`). The console must not say "khớp" for a pair
// the report calls a disagreement, so the mapping is that file's and is not this file's to improve:
//   - ① `escalate` agrees with a human escalation (status `escalated_tier2`);
//   - ① `false_positive` agrees with a human `false_positive` (status `closed_fp`);
//   - any other pair of a ① verdict and a human decision disagrees, a human `benign` (status `closed_benign`)
//     after ① `false_positive` included: ① has no `benign` verdict;
//   - ① `needs_review`, no ① result, and an action that is none of the three are no verdict (the report
//     leaves them out of the denominator): nothing is compared.
// A decision that is not a Tier 1 person's (`auto_closed`, and `closed_confirmed`, which is Tier 2's
// conclusion) is not in the report at all, so it has no comparison: `null`.

export type Agreement = "agree" | "disagree" | "no_verdict";

/** The human decision behind a status, in the report's words; a status that is not a Tier 1 decision has none. */
const HUMAN: Readonly<Record<string, "escalated" | "false_positive" | "benign">> = {
  escalated_tier2: "escalated",
  closed_fp: "false_positive",
  closed_benign: "benign",
};

export function agreementOf(status: string, action: string | null): Agreement | null {
  const human = HUMAN[status];
  if (human === undefined) return null;
  if (action !== "escalate" && action !== "false_positive") return "no_verdict";
  const agrees =
    (action === "escalate" && human === "escalated") ||
    (action === "false_positive" && human === "false_positive");
  return agrees ? "agree" : "disagree";
}
