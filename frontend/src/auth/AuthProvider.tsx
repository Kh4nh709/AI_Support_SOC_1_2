// The session of this tab, for the components: restored on load, confirmed by /api/auth/me, cleared at
// `expiresAt`, on a 401 and on a logout broadcast by another tab (spec §3).
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useLocation, useNavigate } from "react-router";
import { fetchMe, postLogin, postLogout } from "../api/auth";
import { setTokenSource } from "../api/client";
import { isRole } from "../api/types";
import { landingAfterLogin } from "./redirect";
import {
  clearSession,
  forgetSession,
  loadSession,
  requestSessionFromOtherTabs,
  saveSession,
  startSessionSharing,
  type Session,
} from "./session";

export type AuthState = {
  session: Session | null;
  /**
   * False until the session has been restored: read from this tab's storage or from the other tabs, and
   * confirmed by /api/auth/me. A guard must wait for it, or a reload would bounce to the login page.
   */
  ready: boolean;
  /** True from the press of Đăng xuất until the next login: that session ended on purpose. */
  signedOut: boolean;
  /** Posts the credentials, saves the session, and opens the role's home. Throws the ApiError. */
  login(username: string, password: string): Promise<void>;
  /**
   * Clears the session in every tab and opens /login at once, then posts /auth/logout with the old
   * token (an error or a five-second silence is ignored). The promise settles when that post does.
   */
  logout(): Promise<void>;
};

export const AuthContext = createContext<AuthState | null>(null);

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (value === null) throw new Error("useAuth needs an AuthProvider above it");
  return value;
}

/** How long a new tab waits for an open tab to hand it the session. */
const ASK_OTHER_TABS_MS = 300;
/** How long the logout POST may take before it is abandoned; the session has ended without it. */
const LOGOUT_TIMEOUT_MS = 5000;
/** `setTimeout` keeps a 32-bit signed delay; a longer one fires at once. */
const MAX_TIMER_MS = 2 ** 31 - 1;

export function AuthProvider({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [session, setSession] = useState<Session | null>(() => loadSession());
  const [ready, setReady] = useState(false);
  const [signedOut, setSignedOut] = useState(false);
  // The token source of the client reads the ref: it is set with the state, before any child effect runs.
  const sessionRef = useRef<Session | null>(session);
  const locationRef = useRef(location);
  useEffect(() => {
    locationRef.current = location;
  }, [location]);

  const apply = useCallback((next: Session | null) => {
    sessionRef.current = next;
    setSession(next);
  }, []);

  // This tab's session is over (401, expiry): forget it here. It is not broadcast: another tab may have
  // signed in again since, and its session is not ours to end. A guard sends the visitor to /login.
  const endHere = useCallback(() => {
    forgetSession();
    apply(null);
  }, [apply]);

  useEffect(() => {
    setTokenSource(() => sessionRef.current?.token ?? null, endHere);
    return () =>
      setTokenSource(
        () => null,
        () => {},
      );
  }, [endHere]);

  // Answer the new tabs, and close this session when another tab logs out.
  useEffect(() => startSessionSharing(() => apply(null)), [apply]);

  // On load: this tab's storage, or else the open tabs; then /me, because the storage is not trusted.
  useEffect(() => {
    const abort = new AbortController();
    void (async () => {
      let current = sessionRef.current;
      if (current === null) {
        const shared = await requestSessionFromOtherTabs(ASK_OTHER_TABS_MS, abort.signal);
        if (abort.signal.aborted) return;
        // A login in this tab during the wait wins over what another tab had.
        if (shared !== null && sessionRef.current === null) {
          saveSession(shared);
          apply(shared);
        }
        current = sessionRef.current;
      }
      if (current !== null) {
        const asked = current;
        try {
          const me = await fetchMe();
          if (abort.signal.aborted) return;
          if (sessionRef.current?.token === asked.token) {
            if (isRole(me.role)) {
              const confirmed: Session = {
                token: asked.token,
                role: me.role,
                username: me.username,
                expiresAt: me.expires_at,
              };
              saveSession(confirmed);
              apply(confirmed);
            } else {
              endHere(); // a role this UI has no page for
            }
          }
        } catch {
          // A 401 already ended the session through the client's hook. Any other failure (the backend is
          // down) says nothing about the login, so the stored session stands until a call refuses it.
          if (abort.signal.aborted) return;
        }
      }
      setReady(true);
    })();
    return () => abort.abort();
  }, [apply, endHere]);

  // At `expiresAt` the session is over.
  useEffect(() => {
    if (session === null) return;
    const expires = Date.parse(session.expiresAt);
    let timer: ReturnType<typeof setTimeout>;
    const wait = () => Math.min(Math.max(expires - Date.now(), 0), MAX_TIMER_MS);
    const fire = () => {
      if (expires - Date.now() <= 0) endHere();
      else timer = setTimeout(fire, wait()); // the delay was capped, or the timer fired early
    };
    timer = setTimeout(fire, wait());
    return () => clearTimeout(timer);
  }, [session, endHere]);

  const login = useCallback(
    async (username: string, password: string) => {
      const res = await postLogin(username, password);
      if (!isRole(res.role) || typeof res.token !== "string" || res.token === "") {
        throw new Error("the login answer has no usable token or role");
      }
      const next: Session = {
        token: res.token,
        role: res.role,
        username,
        expiresAt: res.expires_at,
      };
      saveSession(next);
      apply(next);
      setSignedOut(false);
      setReady(true);
      navigate(landingAfterLogin(locationRef.current.state, next.role), { replace: true });
    },
    [apply, navigate],
  );

  const logout = useCallback(async () => {
    const token = sessionRef.current?.token ?? null;
    // First, so the guard that sees the session go knows it went on purpose and keeps no return path.
    setSignedOut(true);
    // The session ends here, in every tab, and the page leaves at once: a backend that is slow or down
    // must not leave the user looking at a screen they believe they have signed out of.
    clearSession();
    apply(null);
    navigate("/login", { replace: true });
    if (token === null) return; // nothing left to invalidate on the server
    // Then tell the server, with the token that was the session's (the client has none of its own now,
    // and this call reads none: `apply(null)` above emptied its source before this line runs). A failure
    // only means the token lives on until it expires; a stalled server is given up on after a while.
    const abort = new AbortController();
    const giveUp = setTimeout(() => abort.abort(), LOGOUT_TIMEOUT_MS);
    try {
      await postLogout(token, abort.signal);
    } catch {
      // Ignored on purpose (a refusal, a network error or the timeout).
    } finally {
      clearTimeout(giveUp);
    }
  }, [apply, navigate]);

  const value = useMemo<AuthState>(
    () => ({ session, ready, signedOut, login, logout }),
    [session, ready, signedOut, login, logout],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
