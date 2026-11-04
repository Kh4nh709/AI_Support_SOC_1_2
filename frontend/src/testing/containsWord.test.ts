// The leak-marker search the blind-arm tests use: whole words only.
import { containsWord, wordsFound } from "./containsWord";

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
