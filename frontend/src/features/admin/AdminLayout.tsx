// The frame of every admin page (spec §3): the left sidebar of the canvas, with the seven pages in its
// order, and the page beside it. The app shell (`Shell` in routes.tsx) already gives the header and the one
// `main` landmark; this adds only a navigation, so a page task renders its `h1` and its content and nothing else.
//
// `NavLink` marks the link of the current page with `aria-current="page"`, which is what the canvas's
// own sidebar does and what a screen reader announces. The link text is in `strings.ts`.
import type { ReactNode } from "react";
import { NavLink } from "react-router";
import { S } from "../../strings";

/** The seven pages, in the order of the canvas. */
const PAGES = [
  { to: "/admin/overview", label: S.admin.nav.overview },
  { to: "/admin/users", label: S.admin.nav.users },
  { to: "/admin/llm", label: S.admin.nav.llm },
  { to: "/admin/rules", label: S.admin.nav.rules },
  { to: "/admin/digest", label: S.admin.nav.digest },
  { to: "/admin/labels", label: S.admin.nav.labels },
  { to: "/admin/audit", label: S.admin.nav.audit },
] as const;

const LINK =
  "block rounded-md px-3 py-2.5 text-sm focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text";

export function AdminLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-start gap-6">
      <nav
        aria-label={S.admin.nav.label}
        className="flex w-56 shrink-0 flex-col gap-1 rounded-lg border border-border bg-[#0f141b] p-3"
      >
        {PAGES.map((page) => (
          <NavLink
            key={page.to}
            to={page.to}
            className={({ isActive }) =>
              `${LINK} ${
                isActive
                  ? "bg-[#1c2530] font-semibold text-text"
                  : "text-[#aeb9c6] hover:bg-[#161d27] hover:text-text"
              }`
            }
          >
            {page.label}
          </NavLink>
        ))}
      </nav>
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}
