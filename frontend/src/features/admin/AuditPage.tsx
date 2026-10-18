// `/admin/audit` — a placeholder (P11-T10). P11-T17 replaces this file with the page of spec §4.7.
import { S } from "../../strings";

export function AuditPage() {
  return (
    <section className="space-y-2">
      <h1 className="text-2xl font-semibold">{S.admin.title.audit}</h1>
      <p className="text-sm text-muted">{S.admin.building}</p>
    </section>
  );
}
