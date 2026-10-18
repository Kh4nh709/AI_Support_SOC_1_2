// `/admin/overview` — a placeholder (P11-T10). P11-T11 replaces this file with the page of spec §4.1.
import { S } from "../../strings";

export function OverviewPage() {
  return (
    <section className="space-y-2">
      <h1 className="text-2xl font-semibold">{S.admin.title.overview}</h1>
      <p className="text-sm text-muted">{S.admin.building}</p>
    </section>
  );
}
