// `/admin/rules` — a placeholder (P11-T10). P11-T14 replaces this file with the page of spec §4.4.
import { S } from "../../strings";

export function RulesPage() {
  return (
    <section className="space-y-2">
      <h1 className="text-2xl font-semibold">{S.admin.title.rules}</h1>
      <p className="text-sm text-muted">{S.admin.building}</p>
    </section>
  );
}
