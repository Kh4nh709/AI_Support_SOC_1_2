// The route guard (spec §3.1). The UI hides what a role cannot do; the API is the enforcement.
import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router";
import { S } from "../strings";
import { useAuth } from "./AuthProvider";
import { pathOf } from "./redirect";
import type { Session } from "./session";

/**
 * Renders the children to a signed-in user of one of `roles`. Nobody signed in goes to /login, carrying
 * the page they wanted so the login can return to it. A role that may not be here goes to /queue, which
 * every role may read, and the queue says why (`ForbiddenNotice`). While the session is being restored
 * it decides nothing.
 */
export function RequireRole(props: { roles: readonly Session["role"][]; children: ReactNode }) {
  const { session, ready, signedOut } = useAuth();
  const location = useLocation();
  if (!ready) return <p role="status">{S.common.loading}</p>;
  if (session === null) {
    // After an Đăng xuất there is nothing to return to: the next login starts at the role's home.
    const state = signedOut ? null : { from: pathOf(location) };
    return <Navigate to="/login" replace state={state} />;
  }
  if (!props.roles.includes(session.role)) {
    return <Navigate to="/queue" replace state={{ forbidden: true }} />;
  }
  return <>{props.children}</>;
}

/** The refusal of `RequireRole`, shown where it lands: a route that turned the visitor away sets the flag. */
export function ForbiddenNotice() {
  const location = useLocation();
  const forbidden = (location.state as { forbidden?: unknown } | null)?.forbidden === true;
  if (!forbidden) return null;
  return (
    <p role="alert" className="mb-4 rounded border border-high bg-high-bg px-4 py-2 text-high">
      {S.forbidden}
    </p>
  );
}
