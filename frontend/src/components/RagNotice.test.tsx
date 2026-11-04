// src/components/RagNotice.test.tsx — the notice beside the AI's conclusion when the RAG was not applied
// (P14-T07, DEC-213, spec 4.3). The sentences are the brief's, written out here in full on purpose: a label edited
// in strings.ts alone must fail this file, not follow it.
import { render, screen } from "@testing-library/react";
import { RagNotice } from "./RagNotice";

const TAIL = "AI đã phân tích không có tri thức tham khảo.";

const LABELS = [
  ["rate_limit", "Voyage vượt giới hạn tốc độ"],
  ["timeout", "Voyage quá thời gian chờ"],
  ["auth", "thiếu hoặc sai API key Voyage"],
  ["quota", "Voyage hết hạn mức"],
  ["provider_error", "lỗi phía Voyage"],
  ["vectordb_unreachable", "không kết nối được vector DB"],
] as const;

describe("RagNotice", () => {
  it.each(LABELS)("says the alert's notice for %s", (kind, label) => {
    render(<RagNotice kind={kind} subject="alert" />);
    expect(screen.getByRole("note")).toHaveTextContent(
      `⚠ Không áp dụng RAG cho alert này: ${label} — ${TAIL}`,
    );
  });

  it.each(LABELS)("says the case's notice for %s", (kind, label) => {
    render(<RagNotice kind={kind} subject="case" />);
    expect(screen.getByRole("note")).toHaveTextContent(
      `⚠ Không áp dụng RAG cho case này: ${label} — ${TAIL}`,
    );
  });

  it("says alert on the alert page and never case, and the other way round", () => {
    const { unmount } = render(<RagNotice kind="auth" subject="alert" />);
    expect(screen.getByRole("note").textContent).not.toContain("case");
    unmount();
    render(<RagNotice kind="auth" subject="case" />);
    expect(screen.getByRole("note").textContent).not.toContain("alert");
  });

  it("is the exact sentence, nothing before or after", () => {
    render(<RagNotice kind="auth" subject="alert" />);
    expect(screen.getByRole("note").textContent).toBe(
      "⚠ Không áp dụng RAG cho alert này: thiếu hoặc sai API key Voyage — AI đã phân tích không có tri thức tham khảo.",
    );
  });

  it("shows a kind it has no words for as the code, as text", () => {
    render(<RagNotice kind="<img src=x onerror=alert(1)>" subject="alert" />);
    const note = screen.getByRole("note");
    expect(note.textContent).toContain("<img src=x onerror=alert(1)>");
    expect(note.querySelector("img")).toBeNull();
  });

  it("is a warning mark and words, not colour alone", () => {
    render(<RagNotice kind="quota" subject="alert" />);
    expect(screen.getByRole("note").textContent?.startsWith("⚠ ")).toBe(true);
  });
});
