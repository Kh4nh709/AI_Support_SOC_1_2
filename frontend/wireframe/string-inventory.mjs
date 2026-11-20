// Evaluate only the project's own strings module at build time, before minification
// changes formatter parameter names. Each entry can be found by its full key.
import fs from "node:fs";
import ts from "typescript";
import vm from "node:vm";
import { resolve } from "node:path";

const example = {
  n: 3,
  from: 1,
  to: 20,
  total: 56,
  now: 14,
  then: 2,
  held: 2,
  seen: 2,
  delta: 12,
  tolerance: 2,
  pct: 84,
  floor: 75,
  best: 84,
  min: 1,
  max: 500,
  yearMin: 2020,
  yearMax: 2030,
  id: "RV885310",
  subject: "win-fin-17",
  user: "minh.nguyen",
  username: "minh.nguyen",
  name: "linh.tran",
  who: "linh.tran",
  by: "linh.tran",
  account: "Administrator",
  host: "ad-server",
  server: "ad-server",
  time: "09:42",
  at: "09:42",
  until: "10:00",
  lastSeen: "09:42",
  when: "09:42",
  clock: "10:00",
  left: "18:00",
  day: "20/11",
  range: "24 giờ qua",
  level: "cao",
  role: "Tier 2",
  status: "Đang điều tra",
  severity: "Cao",
  action: "Gỡ chặn IP",
  type: "ip:port",
  target: "192.0.2.11",
  field: "Mức độ",
  declared: "cao",
  system: "vừa",
  reason: "Quá thời gian chờ",
  conclusion: "Xác nhận sự cố",
  value: "192.0.2.11",
  alertId: "gl-673dcc4882ab47fbbac7540f9a9b1000",
  scope: "cùng máy",
  fieldName: "Mức độ",
  source: "ThreatFox",
  country: "VN",
  category: "recon",
};
function formatted(fn) {
  const source = ts.createSourceFile(
    "formatter.ts",
    "const f = " + fn.toString(),
    ts.ScriptTarget.Latest,
    true,
  );
  const arrow = source.statements[0].declarationList.declarations[0].initializer;
  const args = arrow.parameters.map((p) => {
    const name = p.name.getText(source);
    if (name.startsWith("{"))
      return {
        count: 2,
        total: 3,
        scope: example.scope,
        pct: 68,
        floor: 75,
        conclusion: example.conclusion,
        reason: example.reason,
      };
    if (["causes", "parts", "reasons"].includes(name)) return ["dẫn chứng chưa khớp"];
    return example[name] ?? "‹" + name + "›";
  });
  return fn(...args);
}
export function inventory(root) {
  const source = fs.readFileSync(resolve(root, "src/strings.ts"), "utf8");
  const code = ts.transpile(source, {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.CommonJS,
  });
  const exports = {};
  vm.runInNewContext(code, {
    exports,
    require: () => ({ BAND_CODES: ["critical", "high", "medium", "low"] }),
  });
  const rows = [];
  function visit(value, key) {
    if (typeof value === "object")
      for (const [child, v] of Object.entries(value)) visit(v, key ? key + "." + child : child);
    else rows.push([key, typeof value === "function" ? formatted(value) : value]);
  }
  visit(exports.S, "");
  return rows;
}
