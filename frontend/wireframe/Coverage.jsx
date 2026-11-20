import { useState } from "react";
import { screens } from "./data";

export const mapping = {
  appearance: "queue login",
  app: "queue login",
  nav: "queue",
  role: "queue",
  forbidden: "queue",
  live: "queue",
  common: "queue alert cases case soar ti admin-overview login",
  login: "login",
  band: "queue alert case",
  severity: "alert cases case admin-labels",
  confidence: "queue alert case",
  category: "queue alert admin-labels",
  status: "queue alert",
  queue: "queue",
  ai1: "queue alert",
  rag: "alert case admin-knowledge",
  alert: "alert",
  decision: "alert",
  workspace: "queue alert cases case",
  case: "cases case",
  caseStatus: "cases case",
  conclusion: "case",
  headStatus: "case",
  analysis: "alert case",
  ai2: "case",
  "admin.nav": "admin-overview",
  "admin.title": "admin-overview admin-users admin-llm admin-labels admin-knowledge admin-audit",
  "admin.overviewPage": "admin-overview",
  "admin.common":
    "admin-overview admin-users admin-llm admin-labels admin-lab admin-knowledge admin-audit",
  "admin.range": "admin-overview admin-llm admin-audit",
  "admin.reason": "admin-overview admin-users admin-llm admin-labels",
  "admin.bounds": "admin-users admin-llm",
  "admin.usersPage": "admin-users",
  "admin.llmPage": "admin-llm",
  "admin.auditGroup": "admin-audit",
  "admin.eventType": "admin-audit",
  "admin.auditPage": "admin-audit",
  "admin.verdict": "admin-audit",
  "admin.labelsPage": "admin-labels",
  "admin.lab": "admin-lab admin-lab-run",
  "admin.knowledgePage": "admin-knowledge",
  soar: "soar alert",
  ti: "ti",
};
const rows = __WIRE_STRINGS__;
function groupOf(key) {
  return key
    .split(".")
    .slice(0, key.startsWith("admin.") ? 2 : 1)
    .join(".");
}
export function Coverage({ show }) {
  const [search, setSearch] = useState("");
  const needle = search.trim().toLocaleLowerCase("vi");
  return (
    <details className="wf-coverage">
      <summary>Đối chiếu strings.ts · {rows.length} khoá</summary>
      <label>
        Tìm khoá hoặc nội dung
        <input type="search" value={search} onChange={(e) => setSearch(e.target.value)} />
      </label>
      {Object.entries(mapping).map(([group, ids]) => {
        const hits = rows.filter(
          ([key, value]) =>
            groupOf(key) === group &&
            (!needle || (key + " " + value).toLocaleLowerCase("vi").includes(needle)),
        );
        if (!hits.length) return null;
        return (
          <details key={group + "-" + Boolean(needle)} open={needle ? true : undefined}>
            <summary>
              {group} · {hits.length}
            </summary>
            <div>
              {ids.split(" ").map((id) => {
                const screen = screens.find((s) => s[0] === id);
                return (
                  <button key={id} onClick={() => show(screen)}>
                    {screen[1]}
                  </button>
                );
              })}
            </div>
            <dl>
              {hits.map(([key, value]) => (
                <div key={key}>
                  <dt>
                    <code>{key}</code>
                  </dt>
                  <dd>{value}</dd>
                </div>
              ))}
            </dl>
          </details>
        );
      })}
    </details>
  );
}
