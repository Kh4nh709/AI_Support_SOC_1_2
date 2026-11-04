// src/features/tier1/AiCell.test.tsx — the wording of each ① state. What the state IS is decided in
// aiState.ts (and tested there); this only words it.
import { cleanup, render, screen } from "@testing-library/react";
import { S } from "../../strings";
import { AiCell } from "./AiCell";
import type { AiState } from "./aiState";

const show = (state: AiState) => render(<AiCell state={state} />);

/** A `ready` state with nothing held; a test overrides what it is about. */
const READY: Extract<AiState, { kind: "ready" }> = {
  kind: "ready",
  action: "false_positive",
  confidence: null,
  forced: false,
  proposed: null,
  heldBy: [],
};

describe("AiCell", () => {
  it("says 'ẩn — nhánh mù' for hidden, and that is not 'chưa có'", () => {
    show({ kind: "hidden" });
    expect(screen.getByText(S.ai1.hidden)).toBeInTheDocument();
    expect(screen.queryByText(S.ai1.none)).toBeNull();
  });

  it("says 'chưa có' for pending, and that ① is unavailable for unavailable", () => {
    const { unmount } = show({ kind: "pending" });
    expect(screen.getByText(S.ai1.none)).toBeInTheDocument();
    unmount();
    show({ kind: "unavailable", stoppedBy: null });
    expect(screen.getByText(S.ai1.unavailable)).toBeInTheDocument();
  });

  it("says 'chưa có' for none (an archived alert no ① will ever answer), as it does for pending", () => {
    show({ kind: "none" });
    expect(screen.getByText(S.ai1.none)).toBeInTheDocument();
    expect(screen.queryByText(S.ai1.hidden)).toBeNull();
  });

  it("words the action and the confidence of a ready result", () => {
    show({ ...READY, action: "false_positive", confidence: "high" });
    expect(screen.getByText(/FP/)).toHaveTextContent("FP (cao)");
    expect(screen.queryByRole("img")).toBeNull();
  });

  // P14-T03 (DEC-213): ① answers true_positive or false_positive, and the cell says TP and FP.
  it("words a true_positive result as TP", () => {
    show({ ...READY, action: "true_positive", confidence: "medium", proposed: "true_positive" });
    expect(screen.getByText(/TP/)).toHaveTextContent("TP (trung bình)");
    expect(screen.queryByText(/Chuyển tier 2/)).toBeNull();
  });

  it("words a verdict the system held as the system's own Cần xem xét, flagged: the reasons are the alert page's", () => {
    show({
      ...READY,
      action: "needs_review",
      confidence: "medium",
      forced: true,
      proposed: "false_positive",
      heldBy: ["fp_policy:asset_criticality"],
    });
    expect(screen.getByText(/Cần xem xét/)).toHaveTextContent("Cần xem xét (trung bình)");
    expect(screen.getByRole("img", { name: S.ai1.forcedLabel })).toBeInTheDocument();
    expect(screen.queryByText(/tài sản/)).toBeNull();
  });

  it("leaves out the confidence when the result has none, and marks a forced one", () => {
    show({ ...READY, action: "needs_review", confidence: null, forced: true });
    expect(screen.getByText(/Cần xem xét/)).not.toHaveTextContent("(");
    expect(screen.getByRole("img", { name: S.ai1.forcedLabel })).toHaveTextContent(S.ai1.forced);
  });

  it("shows an action it has no label for as the code, the old `escalate` included", () => {
    show({ ...READY, action: "quarantine", confidence: null });
    expect(screen.getByText("quarantine")).toBeInTheDocument();
    cleanup();
    show({ ...READY, action: "escalate", confidence: null });
    expect(screen.getByText("escalate")).toBeInTheDocument();
  });

  it("words a decided alert by the action ① had suggested, or 'chưa có' when it had none", () => {
    const base = {
      kind: "decided" as const,
      confidence: null,
      proposed: null,
      heldBy: [] as string[],
    };
    const { unmount } = show({ ...base, action: "needs_review" });
    expect(screen.getByText("Cần xem xét")).toBeInTheDocument();
    unmount();
    show({ ...base, action: null });
    expect(screen.getByText(S.ai1.none)).toBeInTheDocument();
  });
});
