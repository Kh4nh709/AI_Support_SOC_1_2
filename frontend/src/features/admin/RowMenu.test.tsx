// src/features/admin/RowMenu.test.tsx — the "more actions" disclosure of a table row (P11-T12, spec §4.2: "a row
// menu also offers Vô hiệu hoá"): a button that shows the row's less common actions in place, and hides them
// again on Escape, on a press elsewhere, or when one is chosen.
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { RowMenu, type RowMenuItem } from "./RowMenu";

const ITEMS = (onSelect: () => void): RowMenuItem[] => [
  { id: "deactivate", label: "Vô hiệu hoá", ariaLabel: "Vô hiệu hoá lan.t1", onSelect },
];

function renderMenu(over: Partial<Parameters<typeof RowMenu>[0]> = {}, onSelect = () => {}) {
  return render(
    <>
      <button type="button">Before</button>
      <RowMenu label="Thêm thao tác cho lan.t1" items={ITEMS(onSelect)} {...over} />
      <button type="button">After</button>
    </>,
  );
}

const trigger = () => screen.getByRole("button", { name: "Thêm thao tác cho lan.t1" });
const item = () => screen.queryByRole("button", { name: "Vô hiệu hoá lan.t1" });

describe("the trigger", () => {
  it("is a button named by its label, collapsed, that controls the list of actions", () => {
    renderMenu();
    expect(trigger()).toHaveAttribute("aria-expanded", "false");
    expect(trigger()).toHaveAttribute("type", "button");
    expect(item()).not.toBeInTheDocument();
  });

  it("opens the actions in place, and says it is expanded", async () => {
    const user = userEvent.setup();
    renderMenu();
    await user.click(trigger());
    expect(trigger()).toHaveAttribute("aria-expanded", "true");
    expect(item()).toBeVisible();
    expect(item()).toHaveTextContent("Vô hiệu hoá");
    // aria-controls points at a region that is on the page
    const controls = trigger().getAttribute("aria-controls");
    expect(controls).toBeTruthy();
    expect(document.getElementById(controls ?? "")).toContainElement(item());
  });

  it("closes again when pressed a second time", async () => {
    const user = userEvent.setup();
    renderMenu();
    await user.click(trigger());
    await user.click(trigger());
    expect(trigger()).toHaveAttribute("aria-expanded", "false");
    expect(item()).not.toBeInTheDocument();
  });

  it("is opened from the keyboard, and the focus goes to the first action", async () => {
    const user = userEvent.setup();
    renderMenu();
    trigger().focus();
    await user.keyboard("{Enter}");
    expect(item()).toHaveFocus();
  });
});

describe("closing", () => {
  it("closes on Escape and puts the focus back on the trigger", async () => {
    const user = userEvent.setup();
    renderMenu();
    await user.click(trigger());
    await user.keyboard("{Escape}");
    expect(item()).not.toBeInTheDocument();
    expect(trigger()).toHaveFocus();
    expect(trigger()).toHaveAttribute("aria-expanded", "false");
  });

  it("closes when something else on the page is pressed", async () => {
    const user = userEvent.setup();
    renderMenu();
    await user.click(trigger());
    await user.click(screen.getByRole("button", { name: "After" }));
    expect(item()).not.toBeInTheDocument();
  });

  it("stays open when the press is on the action itself", async () => {
    const user = userEvent.setup();
    renderMenu();
    await user.click(trigger());
    await user.pointer({ keys: "[MouseLeft>]", target: item() as HTMLElement });
    expect(item()).toBeInTheDocument();
  });

  it("closes when Tab leaves it, and does not take the focus back", async () => {
    const user = userEvent.setup();
    renderMenu();
    await user.click(trigger());
    await user.tab();
    expect(item()).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "After" })).toHaveFocus();
  });
});

describe("the row's main button", () => {
  it("is drawn beside the trigger, and a press on it closes the list", async () => {
    const user = userEvent.setup();
    renderMenu({ leading: <button type="button">Đặt lại mật khẩu lan.t1</button> });
    await user.click(trigger());
    expect(item()).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Đặt lại mật khẩu lan.t1" }));
    expect(item()).not.toBeInTheDocument();
  });
});

describe("choosing an action", () => {
  it("calls its handler once, closes the list, and has the focus on the trigger by then", async () => {
    const user = userEvent.setup();
    const seen: (Element | null)[] = [];
    const onSelect = vi.fn(() => {
      seen.push(document.activeElement);
    });
    renderMenu({}, onSelect);
    await user.click(trigger());
    await user.click(item() as HTMLElement);
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(seen[0]).toBe(trigger());
    expect(item()).not.toBeInTheDocument();
  });
});

describe("a disabled menu", () => {
  it("cannot be opened, and says why in its title", async () => {
    const user = userEvent.setup();
    renderMenu({ disabled: true, title: "Bạn không thể tự vô hiệu hoá" });
    expect(trigger()).toBeDisabled();
    expect(trigger()).toHaveAttribute("title", "Bạn không thể tự vô hiệu hoá");
    await user.click(trigger());
    expect(item()).not.toBeInTheDocument();
  });
});

describe("accessibility", () => {
  it("has no axe violation, closed or open", async () => {
    const user = userEvent.setup();
    const { container } = renderMenu();
    const run = () =>
      axe
        .run(container, { rules: { "color-contrast": { enabled: false } } })
        .then((r) => r.violations.map((v) => v.id));
    expect(await run()).toEqual([]);
    await user.click(trigger());
    expect(await run()).toEqual([]);
  });
});
