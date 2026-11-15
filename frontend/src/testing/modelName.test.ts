// src/testing/modelName.test.ts — the G5 guard of the AI analysis panels held against what it must catch and what it must
// let through (DEC-221): the model's name appears nowhere on the page, in its text or in any attribute a person, a screen
// reader or a link could carry.
import { MODEL_NAME, modelNamesIn, readableOf } from "./modelName";

const withText = (text: string): HTMLElement => {
  const probe = document.createElement("p");
  probe.textContent = text;
  return probe;
};

const withAttribute = (name: string, value: string): HTMLElement => {
  const probe = document.createElement("div");
  probe.setAttribute(name, value);
  return probe;
};

describe("the model-name guard", () => {
  it.each([
    "GLM 5.3",
    "glm-5.3",
    "GPT-4",
    "DeepSeek",
    "Claude Opus",
    "Qwen3",
    "Llama 3",
    "Gemini 2.5",
    "Mistral Large",
    "Kimi K2",
    "model: x",
  ])("catches %s in the text of the page", (name) => {
    expect(modelNamesIn(withText(name)), name).toHaveLength(1);
  });

  it.each(["title", "aria-label", "aria-description", "alt", "placeholder", "value"])(
    "catches a name in the %s attribute",
    (attribute) => {
      expect(modelNamesIn(withAttribute(attribute, "GLM 5.3"))).toHaveLength(1);
    },
  );

  it.each(["data-model", "data-testid", "data-anything-at-all"])(
    "catches a name in a %s attribute",
    (attribute) => {
      expect(modelNamesIn(withAttribute(attribute, "glm-5.3"))).toHaveLength(1);
    },
  );

  it("catches a name in the target of a link", () => {
    const link = document.createElement("a");
    link.setAttribute("href", "https://example.test/models/qwen3");
    expect(modelNamesIn(link)).toHaveLength(1);
  });

  it("catches a name in an attribute of a nested element, not only of the root", () => {
    const root = document.createElement("div");
    const inner = document.createElement("span");
    inner.setAttribute("data-source", "deepseek");
    root.append(inner);
    expect(modelNamesIn(root)).toHaveLength(1);
  });

  it("lets through the Vietnamese word for a model, an ordinary page and an attribute with nothing in it", () => {
    for (const ok of [
      "mô hình trả lời sai định dạng",
      "Tri thức (RAG)",
      "Bộ kiểm chứng độc lập",
      "Voyage hết hạn mức",
      "xếp hạng lại",
    ]) {
      expect(modelNamesIn(withText(ok)), ok).toEqual([]);
    }
    const probe = withText("Kết luận");
    probe.setAttribute("data-tone", "high");
    probe.setAttribute("href", "/alerts/112438");
    expect(modelNamesIn(probe)).toEqual([]);
  });

  it("reads the text and every attribute that carries words, and says what it read", () => {
    const link = document.createElement("a");
    link.textContent = "112438";
    link.setAttribute("href", "/alerts/112438");
    link.setAttribute("data-kind", "alert");
    link.setAttribute("title", "mở alert");
    expect(readableOf(link)).toEqual(["112438", "mở alert", "alert", "/alerts/112438"]);
  });

  it("keeps the pattern to model names: it matches no word the panels use", () => {
    for (const word of [
      "Kết luận",
      "Độ tin cậy",
      "Kiểm chứng",
      "Tri thức",
      "Playbook",
      "Nhãn MITRE",
    ]) {
      expect(MODEL_NAME.test(word), word).toBe(false);
    }
  });
});
