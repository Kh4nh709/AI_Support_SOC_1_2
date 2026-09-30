// The login form (spec §3.1). The three refusals of the backend each have their own words; the
// password is held in this component's state only, and goes nowhere but the login request.
import { useRef, useState, type FormEvent } from "react";
import { Navigate, useLocation } from "react-router";
import { ApiError } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { landingAfterLogin } from "../auth/redirect";
import { formatClock } from "../format";
import { S } from "../strings";

/** The words for a failed login. */
function messageFor(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return S.login.invalid;
    if (error.status === 423) {
      const until = (error.body as { locked_until?: unknown } | null)?.locked_until;
      return S.login.locked(formatClock(typeof until === "string" ? until : null));
    }
    if (error.status === 503) return S.login.disabled;
  }
  return S.common.unknownError;
}

const INPUT =
  "w-full rounded border border-border bg-ground px-3 py-2 text-text focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text";

export function LoginPage() {
  const { session, ready, login } = useAuth();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // A second Enter must not post the form again while the first request is in flight.
  const inFlight = useRef(false);

  // Someone who is signed in has no use for the form (a new tab that was just handed a session).
  if (ready && session !== null) {
    return <Navigate to={landingAfterLogin(location.state, session.role)} replace />;
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (failure) {
      setError(messageFor(failure));
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  return (
    <section
      aria-labelledby="login-heading"
      className="mx-auto mt-16 w-full max-w-sm rounded border border-border bg-surface p-6"
    >
      <h1 id="login-heading" className="mb-6 text-lg font-semibold">
        {S.login.title}
      </h1>
      <form onSubmit={(event) => void submit(event)} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1">
          <label htmlFor="login-username" className="text-sm text-muted">
            {S.login.username}
          </label>
          <input
            id="login-username"
            name="username"
            type="text"
            autoComplete="username"
            autoFocus
            required
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            className={INPUT}
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="login-password" className="text-sm text-muted">
            {S.login.password}
          </label>
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className={INPUT}
          />
        </div>
        {error !== null && (
          <p
            role="alert"
            className="rounded border border-critical bg-critical-bg px-3 py-2 text-critical"
          >
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          className="rounded bg-text px-4 py-2 font-medium text-ground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text disabled:opacity-60"
        >
          {S.login.submit}
        </button>
      </form>
    </section>
  );
}
