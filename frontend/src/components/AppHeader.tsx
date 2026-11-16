// The app header (spec §3): the name, the navigation for the role (the SOAR page is every role's), the live indicator, the user and Đăng xuất.
// Nobody signed in (the login page, or while the session is being restored) sees the name alone.
import type { ReactNode } from "react";
import { NavLink } from "react-router";
import { useAuth } from "../auth/AuthProvider";
import { S, labelOf } from "../strings";

const LINK =
  "rounded px-2 py-1 text-muted hover:text-text focus-visible:outline-2 focus-visible:outline-text";
const LINK_ACTIVE = "text-text";

export function AppHeader({
  live,
  soarBadge,
}: {
  live?: ReactNode;
  /** The count of open SOAR tickets, inside the "Phản hồi SOAR" link (SR-T2). A slot, like `live`: it fetches, the header does not. */
  soarBadge?: ReactNode;
}) {
  const { session, logout } = useAuth();
  const canSeeCases = session?.role === "tier2" || session?.role === "admin";
  return (
    <header className="flex items-center gap-4 border-b border-border bg-surface px-6 py-3">
      <span className="text-lg font-semibold">{S.app.name}</span>
      {session !== null && (
        <>
          <nav aria-label={S.nav.label} className="flex items-center gap-2">
            <NavLink
              to="/queue"
              className={({ isActive }) => `${LINK} ${isActive ? LINK_ACTIVE : ""}`}
            >
              {S.nav.queue}
            </NavLink>
            {canSeeCases && (
              <NavLink
                to="/cases"
                className={({ isActive }) => `${LINK} ${isActive ? LINK_ACTIVE : ""}`}
              >
                {S.nav.cases}
              </NavLink>
            )}
            <NavLink
              to="/soar"
              className={({ isActive }) => `${LINK} ${isActive ? LINK_ACTIVE : ""}`}
            >
              {S.nav.soar}
              {soarBadge}
            </NavLink>
            {session.role === "admin" && (
              <NavLink
                to="/admin"
                className={({ isActive }) => `${LINK} ${isActive ? LINK_ACTIVE : ""}`}
              >
                {S.nav.admin}
              </NavLink>
            )}
          </nav>
          <div className="ml-auto flex items-center gap-4">
            {live}
            <span className="text-sm">{session.username}</span>
            <span className="rounded border border-border px-2 py-0.5 text-xs text-muted">
              {labelOf(S.role, session.role)}
            </span>
            <button
              type="button"
              onClick={() => void logout()}
              className="rounded border border-border px-3 py-1 text-sm hover:bg-ground focus-visible:outline-2 focus-visible:outline-text"
            >
              {S.nav.logout}
            </button>
          </div>
        </>
      )}
    </header>
  );
}
