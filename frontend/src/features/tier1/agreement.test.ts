// src/features/tier1/agreement.test.ts — whether ① and the person who decided agree. The mapping is the pilot
// report's (P10-T06, eval/ops_export.py, `Q_PILOT_AGREEMENT` and `_PILOT_VERDICT`): ① `true_positive` (P14-T01, DEC-213: it was `escalate`) agrees with a
// human escalation, ① `false_positive` with a human `false_positive` (status closed_fp); any other pair of a
// ① verdict and a human decision is a disagreement, a human `benign` (closed_benign) after ① `false_positive`
// included; ① `needs_review`, or no ① result, is no verdict and is not compared. The console must say
// what the report counts.
//
// The report reads the human decision from the audit events (`tier1.escalated`, `tier1.decided`), not from the
// alert's status. A Tier 2 conclusion rewrites the status of an escalated alert (`concluded_fp` → closed_fp,
// `concluded_policy_violation` → closed_benign, `confirmed_incident` → closed_confirmed), so the status alone
// would read a Tier 1 escalation as a Tier 1 close, or as no Tier 1 decision at all. Only an escalation writes
// `alerts.case_id` (transitions.py, A11), so a `case_id` says the human decision was an escalation, whatever
// the status is now.
import { agreementOf, humanDecisionOf } from "./agreement";

describe("① true_positive and false_positive (P14-T03, DEC-213)", () => {
  it("lets ① true_positive agree with a human escalation", () => {
    expect(agreementOf("escalated_tier2", "true_positive", null)).toBe("agree");
    expect(agreementOf("closed_fp", "true_positive", 9)).toBe("agree"); // escalated, then Tier 2 closed it
  });

  it("lets ① false_positive agree with a human false_positive close", () => {
    expect(agreementOf("closed_fp", "false_positive", null)).toBe("agree");
  });

  it("makes the crossed pairs disagree, and a human benign close disagree with both", () => {
    expect(agreementOf("closed_fp", "true_positive", null)).toBe("disagree");
    expect(agreementOf("escalated_tier2", "false_positive", null)).toBe("disagree");
    expect(agreementOf("closed_benign", "true_positive", null)).toBe("disagree");
    expect(agreementOf("closed_benign", "false_positive", null)).toBe("disagree");
  });

  it("no longer knows the word `escalate` as a verdict of ①: there is no compatibility layer", () => {
    expect(agreementOf("escalated_tier2", "escalate", null)).toBe("no_verdict");
    expect(agreementOf("closed_fp", "escalate", null)).toBe("no_verdict");
  });
});

describe("agreementOf, the pilot report's mapping", () => {
  it.each([
    ["escalated_tier2", "true_positive", "agree"],
    ["closed_fp", "false_positive", "agree"],
    // any other pair of a verdict and a human decision is a disagreement
    ["escalated_tier2", "false_positive", "disagree"],
    ["closed_fp", "true_positive", "disagree"],
    ["closed_benign", "true_positive", "disagree"],
    // ① has no `benign` verdict: a human benign after ① false_positive disagrees
    ["closed_benign", "false_positive", "disagree"],
  ] as const)("%s after ① %s: %s", (status, action, expected) => {
    expect(agreementOf(status, action, null)).toBe(expected);
  });

  it.each(["escalated_tier2", "closed_fp", "closed_benign"])(
    "is no comparison for %s when ① said needs_review, said nothing, or said a word this UI does not know",
    (status) => {
      expect(agreementOf(status, "needs_review", null)).toBe("no_verdict");
      expect(agreementOf(status, null, null)).toBe("no_verdict");
      // `_PILOT_VERDICT` counts an action that is none of the three as no result
      expect(agreementOf(status, "quarantine_host", null)).toBe("no_verdict");
    },
  );

  it.each(["auto_closed", "closed_confirmed"])(
    "is not asked of %s with no case: no person of Tier 1 decided it",
    (status) => {
      for (const action of ["true_positive", "false_positive", "needs_review", null]) {
        expect(agreementOf(status, action, null)).toBeNull();
        expect(agreementOf(status, action, undefined)).toBeNull();
      }
    },
  );

  it.each(["queued_tier1", "tier1_active", "closed_mystery"])(
    "is not asked of %s, which is no decision",
    (status) => {
      expect(agreementOf(status, "true_positive", null)).toBeNull();
    },
  );
});

describe("an alert Tier 1 escalated and Tier 2 then concluded: the pilot report counts an escalation", () => {
  // The status a Tier 2 conclusion leaves on the alert, with the case the escalation opened.
  const CONCLUDED = ["closed_fp", "closed_benign", "closed_confirmed"] as const;

  it.each(CONCLUDED)(
    "%s with a case, after ① true_positive: agree (Tier 1 escalated it)",
    (status) => {
      expect(agreementOf(status, "true_positive", 9)).toBe("agree");
    },
  );

  it.each(CONCLUDED)(
    "%s with a case, after ① false_positive: disagree (Tier 1 escalated it)",
    (status) => {
      expect(agreementOf(status, "false_positive", 9)).toBe("disagree");
    },
  );

  it.each(CONCLUDED)(
    "%s with a case is no comparison when ① said needs_review, nothing, or an unknown word",
    (status) => {
      expect(agreementOf(status, "needs_review", 9)).toBe("no_verdict");
      expect(agreementOf(status, null, 9)).toBe("no_verdict");
      expect(agreementOf(status, "quarantine_host", 9)).toBe("no_verdict");
    },
  );

  it("reads the case as it comes: a number or a string, and the escalated status itself", () => {
    expect(agreementOf("closed_fp", "true_positive", "9")).toBe("agree");
    expect(agreementOf("escalated_tier2", "true_positive", 9)).toBe("agree");
    expect(agreementOf("escalated_tier2", "false_positive", "9")).toBe("disagree");
  });

  it("does not let a case with no id turn a Tier 1 close into an escalation", () => {
    expect(agreementOf("closed_fp", "false_positive", null)).toBe("agree");
    expect(agreementOf("closed_fp", "false_positive", undefined)).toBe("agree");
    expect(agreementOf("closed_benign", "false_positive", null)).toBe("disagree");
  });
});

describe("humanDecisionOf, the decision the report counts", () => {
  it.each([
    ["escalated_tier2", null, "escalated"],
    ["closed_fp", null, "false_positive"],
    ["closed_benign", null, "benign"],
    ["auto_closed", null, null],
    ["closed_confirmed", null, null],
    ["tier1_active", null, null],
    // a case says the human decision was an escalation, whatever Tier 2 has made of the status since
    ["closed_fp", 9, "escalated"],
    ["closed_benign", 9, "escalated"],
    ["closed_confirmed", 9, "escalated"],
    ["escalated_tier2", 9, "escalated"],
    ["closed_fp", "9", "escalated"],
  ] as const)("%s with case %s is %s", (status, caseId, expected) => {
    expect(humanDecisionOf(status, caseId)).toBe(expected);
  });
});

describe("an archived alert is no decision (DEC-212)", () => {
  // The archive set the old queue aside without review: nobody decided it, so there is no human decision
  // to compare ① with - not a close, and not an escalation either, though the alert may still carry the
  // case of an escalation that happened before (that escalation stays in the audit log as `tier1.escalated`).
  it.each([null, undefined, 9, "9"])("has no human decision, with case %s", (caseId) => {
    expect(humanDecisionOf("archived", caseId)).toBeNull();
  });

  it.each([null, undefined, 9])("is not compared with ①, with case %s", (caseId) => {
    for (const action of [
      "true_positive",
      "false_positive",
      "needs_review",
      "quarantine_host",
      null,
    ]) {
      expect(agreementOf("archived", action, caseId)).toBeNull();
    }
  });
});
