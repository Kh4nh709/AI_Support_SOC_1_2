// The leak-marker search the blind-arm tests use: whole words only.
import { containsWord, phrasesFound, textOf, wordsFound } from "./containsWord";

describe("containsWord", () => {
  it.each([
    ["FP", "AI kết luận: FP (độ tin cậy cao)"],
    ["TP", "TP"],
    ["TP", "(TP)"],
    ["FP", "TP/FP"],
    ["FP", "đánh dấu FP."],
    ["AI kết luận", "xx AI kết luận: TP"],
    ["fp_policy:severity", "held: fp_policy:severity, x"],
  ])("finds %s in %j", (word, text) => {
    expect(containsWord(text, word)).toBe(true);
  });

  it.each([
    ["TP", "SFTP"],
    ["TP", "HTTP/1.1"],
    ["FP", "XFP2"],
    ["FP", "đã_FP"],
    ["TP", "KhôngTP"],
    ["FP", "fp"],
    ["FP", ""],
    ["fp_policy:severity", "fp_policy:severity_x"],
  ])("does not find %s in %j", (word, text) => {
    expect(containsWord(text, word)).toBe(false);
  });

  it("takes a marker with regex characters literally, and an empty marker never matches", () => {
    expect(containsWord("a (b) c", "(b)")).toBe(true);
    expect(containsWord("a b c", "(b)")).toBe(false);
    expect(containsWord("anything", "")).toBe(false);
  });

  it("lists the markers found", () => {
    expect(wordsFound("SFTP and TP", ["FP", "TP", "AI kết luận"])).toEqual(["TP"]);
    expect(wordsFound("HTTP", ["FP", "TP"])).toEqual([]);
  });
});

// Fix round 2 (Minor): `textContent` glues the text of neighbouring elements ("Đề xuất" + "Cần xem xét" read
// "Đề xuấtCần xem xét"), and a whole-word search then loses a marker at the seam. Text is read per text node.
describe("textOf", () => {
  const dom = (html: string): HTMLElement => {
    const root = document.createElement("div");
    root.innerHTML = html;
    return root;
  };

  it("keeps the text of neighbouring elements apart, where textContent glues it", () => {
    const root = dom("<span>Đề xuất</span><p>Cần xem xét</p>");
    expect(root.textContent).toBe("Đề xuấtCần xem xét");
    expect(textOf(root)).toBe("Đề xuất\nCần xem xét");
  });

  it("leaves a label at the edge of an element a word of its own", () => {
    const root = dom("<span>gốc</span><strong>FP</strong><span>Kết luận</span>");
    expect(containsWord(root.textContent ?? "", "FP")).toBe(false); // glued: the seam hides it
    expect(containsWord(textOf(root), "FP")).toBe(true);
  });

  it("does not cut a word or a phrase inside one text node", () => {
    expect(textOf(dom("<p>AI kết luận: <strong>TP</strong> (độ tin cậy cao)</p>"))).toBe(
      "AI kết luận: \nTP\n (độ tin cậy cao)",
    );
    expect(phrasesFound(textOf(dom("<p>độ tin cậy cao</p>")), ["độ tin cậy"])).toEqual([
      "độ tin cậy",
    ]);
  });

  it("is empty for an element with no text", () => {
    expect(textOf(dom("<div><span></span></div>"))).toBe("");
  });
});

describe("phrasesFound", () => {
  it("finds a phrase as a plain substring, glued to a neighbour or not", () => {
    expect(phrasesFound("ĐềxuấtCần xem xét", ["Cần xem xét", "giữ lại"])).toEqual(["Cần xem xét"]);
    expect(phrasesFound("a (b) c", ["(b)", "x"])).toEqual(["(b)"]);
    expect(phrasesFound("anything", [""])).toEqual([]);
  });
});
