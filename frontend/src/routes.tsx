// The route table of the spec §3.1: the queue is P10-T09's, the alert page P10-T10's, the case list and the
// case page P10-T11's.
import { Navigate, Outlet, Route, Routes } from "react-router";
import { useAuth } from "./auth/AuthProvider";
import { ForbiddenNotice, RequireRole } from "./auth/RequireRole";
import { roleHome } from "./auth/redirect";
import type { Role } from "./api/types";
import { AppHeader } from "./components/AppHeader";
import { AlertPage } from "./features/tier1/AlertPage";
import { QueuePage } from "./features/tier1/QueuePage";
import { CasePage } from "./features/tier2/CasePage";
import { CasesPage } from "./features/tier2/CasesPage";
import { LiveIndicator } from "./live/LiveIndicator";
import { LoginPage } from "./pages/LoginPage";

/** Read for all three roles, the same as the API. */
const EVERY_ROLE: readonly Role[] = ["tier1", "tier2", "admin"];
/** The cases are Tier 2's; the admin reads them too. */
const TIER2_UP: readonly Role[] = ["tier2", "admin"];

/** The header, and the page under it. The login page shares it, so the banner and the main landmark are always there. */
function Shell() {
  return (
    <div className="min-h-screen">
      <AppHeader live={<LiveIndicator />} />
      <main className="p-6">
        <ForbiddenNotice />
        <Outlet />
      </main>
    </div>
  );
}

/** `/`: tier1 goes to the queue; tier2 and admin go to the case list. */
function Home() {
  const { session } = useAuth();
  return session === null ? null : <Navigate to={roleHome(session.role)} replace />;
}

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/"
          element={
            <RequireRole roles={EVERY_ROLE}>
              <Home />
            </RequireRole>
          }
        />
        <Route
          path="/queue"
          element={
            <RequireRole roles={EVERY_ROLE}>
              <QueuePage />
            </RequireRole>
          }
        />
        <Route
          path="/alerts/:alertId"
          element={
            <RequireRole roles={EVERY_ROLE}>
              <AlertPage />
            </RequireRole>
          }
        />
        <Route
          path="/cases"
          element={
            <RequireRole roles={TIER2_UP}>
              <CasesPage />
            </RequireRole>
          }
        />
        <Route
          path="/cases/:caseId"
          element={
            <RequireRole roles={TIER2_UP}>
              <CasePage />
            </RequireRole>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
