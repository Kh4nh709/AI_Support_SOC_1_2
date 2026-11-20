// The app header (spec §3): the name, the navigation for the role (the SOAR page and the Threat Intel page are every role's), the live indicator, the user and Đăng xuất.
// The theme picker also works on the login page.
import { useEffect, useLayoutEffect, useState, type ReactNode } from "react";
import { NavLink } from "react-router";
import { useAuth } from "../auth/AuthProvider";
import { S, labelOf } from "../strings";

const LINK = "rounded px-2 py-1 hover:text-text focus-visible:outline-2 focus-visible:outline-text";
const LINK_ACTIVE = "font-semibold text-ai-accent";

const THEME_KEY = "soc.theme";
type Theme = "light" | "dark";

function readTheme(): Theme {
  try {
    return localStorage.getItem(THEME_KEY) === "light" ? "light" : "dark";
  } catch {
    return document.documentElement.dataset.theme === "light" ? "light" : "dark";
  }
}

function ThemePicker() {
  const [theme, setTheme] = useState(readTheme);
  useLayoutEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  useEffect(() => {
    function sync(event: StorageEvent) {
      if (event.key === THEME_KEY || event.key === null) setTheme(readTheme());
    }
    window.addEventListener("storage", sync);
    return () => window.removeEventListener("storage", sync);
  }, []);

  function choose(next: Theme) {
    setTheme(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      /* The choice still applies to this document. */
    }
  }
  return (
    <fieldset className="theme-picker" aria-label={S.appearance.label}>
      {(["light", "dark"] as const).map((value) => (
        <label key={value}>
          <input
            type="radio"
            name="appearance"
            checked={value === theme}
            onChange={() => choose(value)}
          />
          <span>{S.appearance[value]}</span>
        </label>
      ))}
    </fieldset>
  );
}

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
    <header className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-border bg-surface px-4 py-3 sm:px-6">
      <span className="text-lg font-semibold">{S.app.name}</span>
      <ThemePicker />
      {session !== null && (
        <>
          <nav
            aria-label={S.nav.label}
            className="order-last flex max-w-full basis-full flex-wrap items-center gap-x-2 gap-y-1 lg:order-none lg:basis-auto"
          >
            <NavLink
              to="/queue"
              className={({ isActive }) => `${LINK} ${isActive ? LINK_ACTIVE : "text-muted"}`}
            >
              {S.nav.queue}
            </NavLink>
            {canSeeCases && (
              <NavLink
                to="/cases"
                className={({ isActive }) => `${LINK} ${isActive ? LINK_ACTIVE : "text-muted"}`}
              >
                {S.nav.cases}
              </NavLink>
            )}
            <NavLink
              to="/soar"
              className={({ isActive }) => `${LINK} ${isActive ? LINK_ACTIVE : "text-muted"}`}
            >
              {S.nav.soar}
              {soarBadge}
            </NavLink>
            <NavLink
              to="/threat-intel"
              className={({ isActive }) => `${LINK} ${isActive ? LINK_ACTIVE : "text-muted"}`}
            >
              {S.nav.ti}
            </NavLink>
            {session.role === "admin" && (
              <NavLink
                to="/admin"
                className={({ isActive }) => `${LINK} ${isActive ? LINK_ACTIVE : "text-muted"}`}
              >
                {S.nav.admin}
              </NavLink>
            )}
          </nav>
          <div className="ml-auto flex max-w-full flex-wrap items-center gap-x-3 gap-y-1">
            {live}
            <span className="min-w-0 break-all text-sm">{session.username}</span>
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
