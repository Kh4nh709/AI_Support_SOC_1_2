import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "node_modules", "test-results", "playwright-report"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  reactHooks.configs.flat.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    rules: {
      // `dangerouslySetInnerHTML`, `eval` and `new Function` appear nowhere in src (spec §6).
      // src/guards.test.ts counts them; these rules fail `make ui-lint` before the tests run.
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "react-hooks/exhaustive-deps": "error",
    },
  },
);
