// src/pages/LoginPage.test.tsx — the login form against the real AuthProvider and a mocked backend.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { StrictMode } from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { AuthProvider } from "../auth/AuthProvider";
import { S } from "../strings";
import { LoginPage } from "./LoginPage";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  sessionStorage.clear();
});
afterAll(() => server.close());

const expiresAt = () => new Date(Date.now() + 8 * 3_600_000).toISOString();

function Where() {
  const { pathname } = useLocation();
  return <p data-testid="where">{pathname}</p>;
}

function renderLogin(entry: string | { pathname: string; state: unknown } = "/login") {
  return render(
    <StrictMode>
      <MemoryRouter initialEntries={[entry]}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/queue" element={<p>queue page</p>} />
            <Route path="/cases" element={<p>cases page</p>} />
            <Route path="/admin/overview" element={<p>admin overview page</p>} />
            <Route path="/alerts/:id" element={<p>alert page</p>} />
          </Routes>
          <Where />
        </AuthProvider>
      </MemoryRouter>
    </StrictMode>,
  );
}

async function submit(username = "an", password = "s3cret-pw") {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText(S.login.username), username);
  await user.type(screen.getByLabelText(S.login.password), password);
  await user.click(screen.getByRole("button", { name: S.login.submit }));
}

const loginOk = (role: string) =>
  http.post("/api/auth/login", () =>
    HttpResponse.json({ token: "tok-9", role, user_id: 4, expires_at: expiresAt() }),
  );
const meFor = (role: string, username = "an") =>
  http.get("/api/auth/me", () =>
    HttpResponse.json({
      user_id: 4,
      username,
      display_name: "An",
      role,
      expires_at: expiresAt(),
    }),
  );

it("has a password field that is type=password with autocomplete=current-password", () => {
  renderLogin();
  const password = screen.getByLabelText(S.login.password);
  expect(password).toHaveAttribute("type", "password");
  expect(password).toHaveAttribute("autocomplete", "current-password");
  expect(screen.getByLabelText(S.login.username)).toHaveAttribute("autocomplete", "username");
  expect(screen.getByRole("heading", { name: S.login.title })).toBeInTheDocument();
});

it("shows S.login.invalid on a 401", async () => {
  server.use(
    http.post("/api/auth/login", () => HttpResponse.json({ detail: "x" }, { status: 401 })),
  );
  renderLogin();
  await submit();
  expect(await screen.findByRole("alert")).toHaveTextContent(S.login.invalid);
  expect(screen.getByTestId("where")).toHaveTextContent("/login");
  expect(sessionStorage.length).toBe(0);
});

it("shows 'Tài khoản bị khoá đến HH:MM' in +07 on a 423 with locked_until", async () => {
  server.use(
    http.post("/api/auth/login", () =>
      HttpResponse.json(
        { detail: "locked", locked_until: "2026-09-30T08:15:00+00:00" },
        { status: 423 },
      ),
    ),
  );
  renderLogin();
  await submit();
  // 08:15 UTC is 15:15 in Asia/Ho_Chi_Minh, though the test process runs in UTC.
  expect(await screen.findByRole("alert")).toHaveTextContent("Tài khoản bị khoá đến 15:15");
  expect(screen.getByRole("alert")).toHaveTextContent(S.login.locked("15:15"));
});

it("shows S.login.disabled on a 503", async () => {
  server.use(
    http.post("/api/auth/login", () =>
      HttpResponse.json({ detail: "auth disabled: JWT_SECRET unset" }, { status: 503 }),
    ),
  );
  renderLogin();
  await submit();
  expect(await screen.findByRole("alert")).toHaveTextContent(S.login.disabled);
});

it("shows the generic error when the backend cannot be reached or answers otherwise", async () => {
  server.use(http.post("/api/auth/login", () => HttpResponse.error()));
  renderLogin();
  await submit();
  expect(await screen.findByRole("alert")).toHaveTextContent(S.common.unknownError);
});

it("shows the generic error, and stays on the form, when the login answer has no usable expires_at", async () => {
  server.use(
    http.post("/api/auth/login", () =>
      HttpResponse.json({ token: "tok-9", role: "tier1", user_id: 4 }),
    ),
  );
  renderLogin();
  await submit();
  expect(await screen.findByRole("alert")).toHaveTextContent(S.common.unknownError);
  expect(screen.getByTestId("where")).toHaveTextContent("/login");
  expect(sessionStorage.getItem("soc.session")).toBeNull();
});

it("goes to /queue after a tier1 login, and saves the session in sessionStorage", async () => {
  let body: unknown = null;
  server.use(
    http.post("/api/auth/login", async ({ request }) => {
      body = await request.json();
      return HttpResponse.json({
        token: "tok-9",
        role: "tier1",
        user_id: 4,
        expires_at: expiresAt(),
      });
    }),
    meFor("tier1"),
  );
  renderLogin();
  await submit("an", "s3cret-pw");
  expect(await screen.findByText("queue page")).toBeInTheDocument();
  expect(screen.getByTestId("where")).toHaveTextContent("/queue");
  expect(body).toEqual({ username: "an", password: "s3cret-pw" });
  const stored = JSON.parse(sessionStorage.getItem("soc.session") ?? "null") as {
    token: string;
    role: string;
    username: string;
  };
  expect(stored).toMatchObject({ token: "tok-9", role: "tier1", username: "an" });
  // The password is kept nowhere: not in the session, not in the storage.
  expect(JSON.stringify({ ...sessionStorage })).not.toContain("s3cret-pw");
  expect(localStorage.length).toBe(0);
});

it("goes to /cases after a tier2 login", async () => {
  server.use(loginOk("tier2"), meFor("tier2"));
  renderLogin();
  await submit();
  expect(await screen.findByText("cases page")).toBeInTheDocument();
  expect(screen.getByTestId("where")).toHaveTextContent("/cases");
});

it("goes to /admin/overview after an admin login", async () => {
  server.use(loginOk("admin"), meFor("admin"));
  renderLogin();
  await submit();
  expect(await screen.findByText("admin overview page")).toBeInTheDocument();
  expect(screen.getByTestId("where")).toHaveTextContent("/admin/overview");
});

it("returns to the page a lost session came from, when the login page was reached from one", async () => {
  server.use(loginOk("tier1"), meFor("tier1"));
  renderLogin({ pathname: "/login", state: { from: "/alerts/12?tab=log" } });
  await submit();
  expect(await screen.findByText("alert page")).toBeInTheDocument();
  expect(screen.getByTestId("where")).toHaveTextContent("/alerts/12");
});

it("does not follow a `from` that leaves the app", async () => {
  server.use(loginOk("tier1"), meFor("tier1"));
  renderLogin({ pathname: "/login", state: { from: "//evil.example/x" } });
  await submit();
  expect(await screen.findByText("queue page")).toBeInTheDocument();
});

it("disables the button while the request is in flight, so nothing is posted twice", async () => {
  let posts = 0;
  server.use(
    http.post("/api/auth/login", async () => {
      posts += 1;
      await new Promise((r) => setTimeout(r, 150));
      return HttpResponse.json({ token: "t", role: "tier1", user_id: 4, expires_at: expiresAt() });
    }),
    meFor("tier1"),
  );
  renderLogin();
  const user = userEvent.setup();
  await user.type(screen.getByLabelText(S.login.username), "an");
  await user.type(screen.getByLabelText(S.login.password), "pw{Enter}{Enter}");
  await waitFor(() => expect(screen.getByRole("button", { name: S.login.submit })).toBeDisabled());
  expect(await screen.findByText("queue page")).toBeInTheDocument();
  expect(posts).toBe(1);
});

it("sends a signed-in visitor of /login to their home", async () => {
  sessionStorage.setItem(
    "soc.session",
    JSON.stringify({ token: "tok", role: "tier2", username: "bo", expiresAt: expiresAt() }),
  );
  server.use(meFor("tier2", "bo"));
  renderLogin();
  expect(await screen.findByText("cases page")).toBeInTheDocument();
});
