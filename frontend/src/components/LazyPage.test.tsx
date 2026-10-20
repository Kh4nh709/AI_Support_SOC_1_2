// src/components/LazyPage.test.tsx — a page that is fetched when its route opens: the waiting line while it comes, and
// a failure that says so (and offers a reload) where React would otherwise unmount the whole tree.
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { lazy, type ReactNode } from "react";
import { MemoryRouter } from "react-router";
import { S } from "../strings";
import { LazyPage, isChunkLoadFailure } from "./LazyPage";

/** A page whose module arrives when `settle` is called: with the component, or with a failure. */
function pageOnItsWay() {
  let settle: (outcome: "arrives" | "fails") => void = () => {};
  const Page = lazy(
    () =>
      new Promise<{ default: () => ReactNode }>((resolve, reject) => {
        settle = (outcome) =>
          outcome === "arrives"
            ? resolve({ default: () => <h1>trang đã tới</h1> })
            : reject(new Error("Failed to fetch dynamically imported module"));
      }),
  );
  return { Page, settle: (outcome: "arrives" | "fails") => settle(outcome) };
}

function renderPage(page: ReactNode, reload = () => {}) {
  return render(
    <MemoryRouter>
      <LazyPage reload={reload}>{page}</LazyPage>
    </MemoryRouter>,
  );
}

describe("isChunkLoadFailure", () => {
  it.each([
    "Failed to fetch dynamically imported module: https://soc.example/assets/UsersPage-C-VtxXH1.js",
    "error loading dynamically imported module",
    "Importing a module script failed.",
    "Unable to preload CSS for /assets/index-H_Bvw5AH.css",
    "ChunkLoadError: Loading chunk 3 failed.",
    "FAILED TO FETCH DYNAMICALLY IMPORTED MODULE",
  ])("reads %j as a chunk that could not be fetched", (message) => {
    expect(isChunkLoadFailure(new Error(message))).toBe(true);
  });

  it.each<[string, unknown]>([
    ["a TypeError", new TypeError("Cannot read properties of undefined (reading 'rows')")],
    ["a React error", new Error("Minified React error #310")],
    ["a RangeError", new RangeError("Invalid array length")],
    ["a string", "a string that was thrown"],
    ["null", null],
    ["undefined", undefined],
  ])("does not read %s as one", (_what, thrown) => {
    expect(isChunkLoadFailure(thrown)).toBe(false);
  });
});

describe("LazyPage", () => {
  it("shows the waiting line while the page is on its way, and the page when it arrives", async () => {
    const { Page, settle } = pageOnItsWay();
    renderPage(<Page />);
    expect(screen.getByRole("status")).toHaveTextContent(S.common.loading);
    expect(screen.queryByRole("heading")).not.toBeInTheDocument();
    settle("arrives");
    expect(await screen.findByRole("heading", { name: "trang đã tới" })).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("says the page could not be loaded, with a reload and the way back, when the fetch fails", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const reload = vi.fn();
      const { Page, settle } = pageOnItsWay();
      renderPage(<Page />, reload);
      settle("fails");
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(S.admin.common.loadError);
      expect(screen.queryByRole("status")).not.toBeInTheDocument();
      expect(screen.getByRole("link", { name: S.nav.queue })).toHaveAttribute("href", "/queue");
      expect(reload).not.toHaveBeenCalled();
      await userEvent.setup().click(screen.getByRole("button", { name: S.common.retry }));
      expect(reload).toHaveBeenCalledTimes(1);
    } finally {
      logged.mockRestore();
    }
  });

  it("does not call a bug of the page a load failure: its own text, no reload, and the error logged alone", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const reload = vi.fn();
      const bug = new TypeError("Cannot read properties of undefined (reading 'rows')");
      const Broken = (): ReactNode => {
        throw bug;
      };
      renderPage(<Broken />, reload);
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(S.admin.common.renderError);
      expect(alert).not.toHaveTextContent(S.admin.common.loadError);
      expect(screen.queryByRole("button", { name: S.common.retry })).not.toBeInTheDocument();
      expect(screen.queryByRole("status")).not.toBeInTheDocument();
      expect(reload).not.toHaveBeenCalled();
      // `componentDidCatch` logs the error and nothing else: not the component stack, which names props.
      expect(logged).toHaveBeenCalledWith(bug);
      expect(
        logged.mock.calls.some((args) =>
          args.some((a) => typeof a === "object" && a !== null && "componentStack" in a),
        ),
      ).toBe(false);
    } finally {
      logged.mockRestore();
    }
  });

  it("reloads once per click on Thử lại, and a failure that comes back does not loop", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const reload = vi.fn();
      const { Page, settle } = pageOnItsWay();
      renderPage(<Page />, reload);
      settle("fails");
      const user = userEvent.setup();
      await user.click(await screen.findByRole("button", { name: S.common.retry }));
      // The reload of a tab starts over, and the page fails again: the same text is still there, and the
      // boundary has called nothing of its own in between.
      await vi.dynamicImportSettled();
      expect(reload).toHaveBeenCalledTimes(1);
      expect(screen.getByRole("alert")).toHaveTextContent(S.admin.common.loadError);
      await user.click(screen.getByRole("button", { name: S.common.retry }));
      expect(reload).toHaveBeenCalledTimes(2);
    } finally {
      logged.mockRestore();
    }
  });

  it("shows what is not lazy at once, with no waiting line", () => {
    renderPage(<p>đã có sẵn</p>);
    expect(screen.getByText("đã có sẵn")).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});
