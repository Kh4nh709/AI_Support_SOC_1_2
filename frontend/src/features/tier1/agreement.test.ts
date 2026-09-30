// src/features/tier1/agreement.test.ts — whether ① and the person who decided agree. The mapping is the pilot
// report's (P10-T06, eval/ops_export.py, `Q_PILOT_AGREEMENT` and `_PILOT_VERDICT`): ① `escalate` agrees with a
// human escalation, ① `false_positive` with a human `false_positive` (status closed_fp); any other pair of a
// ① verdict and a human decision is a disagreement, a human `benign` (closed_benign) after ① `false_positive`
// included; ① `needs_review`, or no ① result, is no verdict and is not compared. The console must say
// what the report counts.
import { agreementOf } from "./agreement";

describe("agreementOf, the pilot report's mapping", () => {
  it.each([
    ["escalated_tier2", "escalate", "agree"],
    ["closed_fp", "false_positive", "agree"],
    // any other pair of a verdict and a human decision is a disagreement
    ["escalated_tier2", "false_positive", "disagree"],
    ["closed_fp", "escalate", "disagree"],
    ["closed_benign", "escalate", "disagree"],
    // ① has no `benign` verdict: a human benign after ① false_positive disagrees
    ["closed_benign", "false_positive", "disagree"],
  ] as const)("%s after ① %s: %s", (status, action, expected) => {
    expect(agreementOf(status, action)).toBe(expected);
  });

  it.each(["escalated_tier2", "closed_fp", "closed_benign"])(
    "is no comparison for %s when ① said needs_review, said nothing, or said a word this UI does not know",
    (status) => {
      expect(agreementOf(status, "needs_review")).toBe("no_verdict");
      expect(agreementOf(status, null)).toBe("no_verdict");
      // `_PILOT_VERDICT` counts an action that is none of the three as no result
      expect(agreementOf(status, "quarantine_host")).toBe("no_verdict");
    },
  );

  it.each(["auto_closed", "closed_confirmed"])(
    "is not asked of %s: no person of Tier 1 decided it",
    (status) => {
      for (const action of ["escalate", "false_positive", "needs_review", null]) {
        expect(agreementOf(status, action)).toBeNull();
      }
    },
  );

  it.each(["queued_tier1", "tier1_active", "closed_mystery"])(
    "is not asked of %s, which is no decision",
    (status) => {
      expect(agreementOf(status, "escalate")).toBeNull();
    },
  );
});
