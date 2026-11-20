import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HashRouter, useLocation, useNavigate } from "react-router";
import { AppRoutes } from "../src/routes";
import { AuthContext } from "../src/auth/AuthProvider";
import { ApiError } from "../src/api/client";
import { S } from "../src/strings";
import { screens, settings, roles, me, scenario, alertId } from "./data";
import { installTransport } from "./transport";
import "../src/styles.css";
import "./preview.css";
import { Coverage } from "./Coverage";
import { growCluster } from "./queue";
installTransport();
const requested = settings.get("man");
const entry = screens.find((s) => s[0] === requested);
if (!location.hash)
  history.replaceState(
    null,
    "",
    location.pathname +
      location.search +
      "#" +
      (entry?.[2] ||
        (requested === "missing" ? "/alerts/missing" : requested === "forbidden" ? "/admin" : "/")),
  );
const initialPath = location.hash.slice(1).split("?")[0];
const initialRole =
  settings.get("role") ||
  (initialPath.startsWith("/admin") && requested !== "forbidden"
    ? "admin"
    : initialPath.startsWith("/cases")
      ? "tier2"
      : "tier1");
const query = new QueryClient({
  defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
});
const modes = [
  ["du-lieu", "Có dữ liệu"],
  ["dang-tai", "Đang tải"],
  ["rong", "Rỗng"],
  ["loi", "Lỗi"],
  ["offline", S.live.off],
];
function reload(patch, path) {
  const url = new URL(location.href);
  Object.entries(patch).forEach(([k, v]) => url.searchParams.set(k, v));
  url.hash = path;
  location.assign(url);
  if (url.search === location.search) location.reload();
}
function Demo() {
  const { pathname } = useLocation(),
    navigate = useNavigate();
  const role = Object.hasOwn(roles, initialRole) ? initialRole : "tier1";
  const token = "preview." + btoa(JSON.stringify({ sub: me.user_id })) + ".sample";
  const [session, setSession] = useState(
    initialPath === "/login"
      ? null
      : { role, username: roles[role], token, expiresAt: "2099-01-01T00:00:00Z" },
  );
  Object.assign(me, { role, username: session?.username || roles[role] });
  const screen =
    screens.find((s) => pathname === s[2]) ||
    screens.find(
      (s) =>
        (s[0] === "case" && pathname.startsWith("/cases/")) ||
        (s[0] === "alert" && pathname.startsWith("/alerts/")) ||
        (s[0] === "admin-lab-run" && pathname.startsWith("/admin/lab/")),
    );
  const [gray, setGray] = useState(settings.get("mau") === "xam"),
    [mobile, setMobile] = useState(settings.get("kho") === "mobile");
  React.useEffect(() => {
    const url = new URL(location.href);
    url.searchParams.set("mau", gray ? "xam" : "mau");
    url.searchParams.set("kho", mobile ? "mobile" : "desktop");
    history.replaceState(history.state, "", url);
  }, [gray, mobile]);
  const framed = settings.has("frame");
  React.useEffect(() => {
    if (scenario !== "growth" || !pathname.startsWith("/alerts/")) return;
    const timer = setTimeout(() => {
      if (growCluster()) void query.invalidateQueries({ queryKey: ["alert", alertId] });
    }, 1800);
    return () => clearTimeout(timer);
  }, [pathname]);
  document.documentElement.dataset.gray = gray ? "1" : "0";
  const canRead = (screen) =>
    screen[0].startsWith("admin-")
      ? role === "admin"
      : !screen[2].startsWith("/cases") || role !== "tier1";
  // The catalogue offers a labelled preview for every role. Inside a screen
  // the navigation and the screen picker both respect the active role.
  const show = (screen) => {
    const previewRole = pathname === "/" && !canRead(screen) ? screen[3] : role;
    reload({ man: screen[0], role: previewRole, tt: "du-lieu" }, screen[2]);
  };
  const extras =
    screen?.[0] === "alert"
      ? [
          ["growth", "Cụm tăng lúc đang đọc"],
          ["reopen", S.decision.reopen],
        ]
      : screen?.[0] === "case"
        ? [
            ["idle", "Chưa phân tích"],
            ["running", "Đang chạy ②"],
            ["stalled", "Treo"],
            ["failed", "Lỗi ②"],
            ["quota", "Hết lượt"],
          ]
        : [];
  if (screen?.[0] === "alert")
    extras.push(
      ["blind", S.ai1.hidden],
      ["pending", "Đang phân tích ①"],
      ["unavailable", S.ai1.unavailable],
    );
  if (screen?.[0] === "login")
    extras.push(
      ["locked", "Tài khoản bị khoá"],
      ["disabled", S.login.disabled],
      ["invalid", S.login.invalid],
    );
  if (screen?.[0] === "admin-labels") extras.push(["frozen", "Đóng băng"]);
  const auth = {
    ready: true,
    session,
    signedOut: session === null,
    logout: async () => {
      query.clear();
      setSession(null);
      navigate("/login");
    },
    login: async (username) => {
      if (scenario === "locked")
        throw new ApiError(423, null, { locked_until: "2026-11-20T03:00:00Z" });
      if (scenario === "disabled") throw new ApiError(503, null);
      if (scenario === "invalid" || scenario === "loi") throw new ApiError(401, null);
      setSession({ role, username, token });
      navigate(role === "admin" ? "/admin/overview" : role === "tier2" ? "/cases" : "/queue");
    },
  };
  const iframeUrl = new URL(location.href);
  iframeUrl.searchParams.set("frame", "1");
  iframeUrl.searchParams.set("mau", gray ? "xam" : "mau");
  return (
    <>
      <div className="wf-tools" hidden={framed}>
        <strong>Wireframe</strong>
        <label>
          Màn hình
          <select
            value={screen?.[0] || "catalog"}
            onChange={(e) =>
              e.target.value === "catalog"
                ? navigate("/")
                : show(screens.find((s) => s[0] === e.target.value))
            }
          >
            <option value="catalog">Danh mục</option>
            {screens
              .filter((s) => pathname === "/" || canRead(s))
              .map((s) => (
                <option key={s[0]} value={s[0]}>
                  {s[1]}
                </option>
              ))}
          </select>
        </label>
        <label>
          Vai trò
          <select value={role} onChange={(e) => reload({ role: e.target.value }, pathname)}>
            {Object.entries(S.role).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label>
          Trạng thái
          <select value={scenario} onChange={(e) => reload({ tt: e.target.value }, pathname)}>
            {[...modes, ...extras].map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <button aria-pressed={gray} onClick={() => setGray(!gray)}>
          Màu
        </button>
        <button aria-pressed={mobile} onClick={() => setMobile(!mobile)}>
          375 px
        </button>
      </div>
      {mobile && !framed ? (
        <iframe title="Bố cục 375 px" src={iframeUrl.href} />
      ) : pathname === "/" ? (
        <main className="wf-catalog">
          <h1>Danh mục wireframe</h1>
          <div>
            {screens.map((s) => (
              <button key={s[0]} onClick={() => show(s)}>
                <strong>{s[1]}</strong>
                <code>{s[2]}</code>
                <small>
                  {s[0] === "login"
                    ? "Trước đăng nhập"
                    : s[0].startsWith("admin")
                      ? "Admin"
                      : s[2].startsWith("/cases")
                        ? "Tier 2 · Admin"
                        : "Tier 1 · Tier 2 · Admin"}
                </small>
              </button>
            ))}
          </div>
          <Coverage show={show} />
        </main>
      ) : (
        <AuthContext.Provider value={auth}>
          <AppRoutes />
        </AuthContext.Provider>
      )}
    </>
  );
}
createRoot(document.getElementById("root")).render(
  <HashRouter>
    <QueryClientProvider client={query}>
      <Demo />
    </QueryClientProvider>
  </HashRouter>,
);
