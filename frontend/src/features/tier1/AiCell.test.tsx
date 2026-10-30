// src/features/tier1/AiCell.test.tsx — the wording of each ① state. What the state IS is decided in
// aiState.ts (and tested there); this only words it.
import { render, screen } from "@testing-library/react";
import { S } from "../../strings";
import { AiCell } from "./AiCell";
import type { AiState } from "./aiState";

const show = (state: AiState) => render(<AiCell state={state} />);

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
    show({ kind: "ready", action: "false_positive", confidence: "high", forced: false });
    expect(screen.getByText(/Dương tính giả/)).toHaveTextContent("Dương tính giả (cao)");
    expect(screen.queryByRole("img")).toBeNull();
  });

  it("leaves out the confidence when the result has none, and marks a forced one", () => {
    show({ kind: "ready", action: "escalate", confidence: null, forced: true });
    expect(screen.getByText(/Chuyển tier 2/)).not.toHaveTextContent("(");
    expect(screen.getByRole("img", { name: S.ai1.forcedLabel })).toHaveTextContent(S.ai1.forced);
  });

  it("shows an action it has no label for as the code", () => {
    show({ kind: "ready", action: "quarantine", confidence: null, forced: false });
    expect(screen.getByText("quarantine")).toBeInTheDocument();
  });

  it("words a decided alert by the action ① had suggested, or 'chưa có' when it had none", () => {
    const { unmount } = show({ kind: "decided", action: "needs_review", confidence: null });
    expect(screen.getByText("Cần xem xét")).toBeInTheDocument();
    unmount();
    show({ kind: "decided", action: null, confidence: null });
    expect(screen.getByText(S.ai1.none)).toBeInTheDocument();
  });
});
