// The route table of the spec §3.1: the queue is P10-T09's, the alert page P10-T10's, the case list and the
// case page P10-T11's. The admin console (P11-T10, admin spec §3) is `/admin` and its seven pages.
import type { ReactNode } from "react";
import { Navigate, Outlet, Route, Routes } from "react-router";
import { useAuth } from "./auth/AuthProvider";
import { ForbiddenNotice, RequireRole } from "./auth/RequireRole";
import { roleHome } from "./auth/redirect";
import type { Role } from "./api/types";
import { CASE_ROLES } from "./caseAccess";
import { AppHeader } from "./components/AppHeader";
import { AdminLayout } from "./features/admin/AdminLayout";
import { AuditPage } from "./features/admin/AuditPage";
import { DigestPage } from "./features/admin/DigestPage";
import { LabelsPage } from "./features/admin/LabelsPage";
import { LlmPage } from "./features/admin/LlmPage";
import { OverviewPage } from "./features/admin/OverviewPage";
import { RulesPage } from "./features/admin/RulesPage";
import { UsersPage } from "./features/admin/UsersPage";
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

/** A page of the console: guarded for the admin, and under the sidebar. */
function AdminPage({ children }: { children: ReactNode }) {
  return (
    <RequireRole roles={ADMIN_ONLY}>
      <AdminLayout>{children}</AdminLayout>
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
