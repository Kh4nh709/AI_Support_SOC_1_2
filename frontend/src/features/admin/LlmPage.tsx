// `/admin/llm` — a placeholder (P11-T10). P11-T13 replaces this file with the page of spec §4.3.
import { S } from "../../strings";

export function LlmPage() {
  return (
    <section className="space-y-2">
      <h1 className="text-2xl font-semibold">{S.admin.title.llm}</h1>
      <p className="text-sm text-muted">{S.admin.building}</p>
    </section>
  );
}
