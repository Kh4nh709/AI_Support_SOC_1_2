// src/components/LazyPage.test.tsx — a page that is fetched when its route opens: the waiting line while it comes, and
// a failure that says so (and offers a reload) where React would otherwise unmount the whole tree.
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { lazy, type ReactNode } from "react";
import { MemoryRouter } from "react-router";
import { S } from "../strings";
import { LazyPage } from "./LazyPage";

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

  it("shows what is not lazy at once, with no waiting line", () => {
    renderPage(<p>đã có sẵn</p>);
    expect(screen.getByText("đã có sẵn")).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});
