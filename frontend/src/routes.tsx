// The route table of the spec §3.1: the queue is P10-T09's, the alert page P10-T10's, the case list and the
// case page P10-T11's. The admin console (P11-T10, admin spec §3) is `/admin` and its pages (`/admin/knowledge` is
// DEC-210's, P13-T06; `/admin/lab` and `/admin/lab/:runId`, the lab labelling, are DEC-213's, P14-T10).
import { lazy, type ReactNode } from "react";
import { Navigate, Outlet, Route, Routes, useLocation } from "react-router";
import { useAuth } from "./auth/AuthProvider";
import { ForbiddenNotice, RequireRole } from "./auth/RequireRole";
import { roleHome } from "./auth/redirect";
import type { Role } from "./api/types";
import { CASE_ROLES } from "./caseAccess";
import { AppHeader } from "./components/AppHeader";
import { LazyPage } from "./components/LazyPage";
import { AdminLayout } from "./features/admin/AdminLayout";
import { AlertPage } from "./features/tier1/AlertPage";
import { QueuePage } from "./features/tier1/QueuePage";
import { CasePage } from "./features/tier2/CasePage";
import { CasesPage } from "./features/tier2/CasesPage";
import { LiveIndicator } from "./live/LiveIndicator";
import { LoginPage } from "./pages/LoginPage";

/** Read for all three roles, the same as the API. */
const EVERY_ROLE: readonly Role[] = ["tier1", "tier2", "admin"];
/** The cases are Tier 2's; the admin reads them too (the alert page links to a case by the same list). */
const TIER2_UP = CASE_ROLES;
/** The admin console is the admin's alone; the API refuses the others on its own (and writes `authz.denied`). */
const ADMIN_ONLY: readonly Role[] = ["admin"];

// The pages of the console are fetched when their route first renders (P11-T20 row 56), so the tier1 and tier2
// pages do not carry the admin console in the main bundle. `RequireRole` wraps them, so a role that is turned away never
// asks for one. They are named exports, hence the `default` of the module `lazy` wants. Any other file that imports one
// of these statically would put it back in the main bundle: routesLazy.test.tsx reads this file for that, and `make
// ui-build` shows the chunks.
const OverviewPage = lazy(() =>
  import("./features/admin/OverviewPage").then((m) => ({ default: m.OverviewPage })),
);
const UsersPage = lazy(() =>
  import("./features/admin/UsersPage").then((m) => ({ default: m.UsersPage })),
);
const LlmPage = lazy(() =>
  import("./features/admin/LlmPage").then((m) => ({ default: m.LlmPage })),
);
const RulesPage = lazy(() =>
  import("./features/admin/RulesPage").then((m) => ({ default: m.RulesPage })),
);
const DigestPage = lazy(() =>
  import("./features/admin/DigestPage").then((m) => ({ default: m.DigestPage })),
);
const LabelsPage = lazy(() =>
  import("./features/admin/LabelsPage").then((m) => ({ default: m.LabelsPage })),
);
const LabRunsPage = lazy(() =>
  import("./features/admin/LabRunsPage").then((m) => ({ default: m.LabRunsPage })),
);
const LabRunPage = lazy(() =>
  import("./features/admin/LabRunPage").then((m) => ({ default: m.LabRunPage })),
);
const KnowledgePage = lazy(() =>
  import("./features/admin/KnowledgePage").then((m) => ({ default: m.KnowledgePage })),
);
const AuditPage = lazy(() =>
  import("./features/admin/AuditPage").then((m) => ({ default: m.AuditPage })),
);

/**
 * A page of the console: guarded for the admin, and under the sidebar. The sidebar is not lazy, so it is there while
 * the page comes; `LazyPage` shows the waiting line in the page's place, and the failure if the page cannot be fetched.
 * Its `key` is the path: the next route starts clean and does not inherit the failure of the last.
 */
function AdminPage({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  return (
    <RequireRole roles={ADMIN_ONLY}>
      <AdminLayout>
        <LazyPage key={pathname}>{children}</LazyPage>
      </AdminLayout>
    </RequireRole>
  );
}

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

/** `/`: tier1 goes to the queue, tier2 to the case list, admin to the console's overview. */
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
        <Route
          path="/admin"
          element={
            <RequireRole roles={ADMIN_ONLY}>
              <Navigate to="/admin/overview" replace />
            </RequireRole>
          }
        />
        <Route
          path="/admin/overview"
          element={
            <AdminPage>
              <OverviewPage />
            </AdminPage>
          }
        />
        <Route
          path="/admin/users"
          element={
            <AdminPage>
              <UsersPage />
            </AdminPage>
          }
        />
        <Route
          path="/admin/llm"
          element={
            <AdminPage>
              <LlmPage />
            </AdminPage>
          }
        />
        <Route
          path="/admin/rules"
          element={
            <AdminPage>
              <RulesPage />
            </AdminPage>
          }
        />
        <Route
          path="/admin/digest"
          element={
            <AdminPage>
              <DigestPage />
            </AdminPage>
          }
        />
        <Route
          path="/admin/labels"
          element={
            <AdminPage>
              <LabelsPage />
            </AdminPage>
          }
        />
        <Route
          path="/admin/lab"
          element={
            <AdminPage>
              <LabRunsPage />
            </AdminPage>
          }
        />
        <Route
          path="/admin/lab/:runId"
          element={
            <AdminPage>
              <LabRunPage />
            </AdminPage>
          }
        />
        <Route
          path="/admin/knowledge"
          element={
            <AdminPage>
              <KnowledgePage />
            </AdminPage>
          }
        />
        <Route
          path="/admin/audit"
          element={
            <AdminPage>
              <AuditPage />
            </AdminPage>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
