// `/admin/users` — a placeholder (P11-T10). P11-T12 replaces this file with the page of spec §4.2.
import { S } from "../../strings";

export function UsersPage() {
  return (
    <section className="space-y-2">
      <h1 className="text-2xl font-semibold">{S.admin.title.users}</h1>
      <p className="text-sm text-muted">{S.admin.building}</p>
    </section>
  );
}
