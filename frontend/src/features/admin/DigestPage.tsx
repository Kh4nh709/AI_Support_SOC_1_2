// `/admin/digest` — a placeholder (P11-T10). P11-T15 replaces this file with the page of spec §4.5.
import { S } from "../../strings";

export function DigestPage() {
  return (
    <section className="space-y-2">
      <h1 className="text-2xl font-semibold">{S.admin.title.digest}</h1>
      <p className="text-sm text-muted">{S.admin.building}</p>
    </section>
  );
}
