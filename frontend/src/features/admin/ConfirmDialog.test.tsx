// src/features/admin/ConfirmDialog.test.tsx — the confirmation dialog of the admin console (spec §3): a
// modal with its focus kept inside, Esc to cancel, and a confirm that cannot be pressed twice.
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { StrictMode, useState, type ReactNode } from "react";
import { S } from "../../strings";
import { ConfirmDialog, type ConfirmDialogProps } from "./ConfirmDialog";

type Over = Partial<ConfirmDialogProps>;

/**
 * A page with a button that opens the dialog, as a page task will use it: the dialog is mounted while it
 * is open. `Before` and `After` are focusable things outside it, which a missing trap would let Tab reach.
 */
function Page({ over = {}, startOpen = false }: { over?: Over; startOpen?: boolean }) {
  const [open, setOpen] = useState(startOpen);
  return (
    <>
      <button type="button">Before</button>
      <button type="button" onClick={() => setOpen(true)}>
        Opener
      </button>
      {open && (
        <ConfirmDialog
          title="Vô hiệu hoá tuan.t1?"
          confirmLabel="Vô hiệu hoá"
          onConfirm={() => setOpen(false)}
          onCancel={() => setOpen(false)}
          {...over}
        >
          <p>Lê Tuấn bị đăng xuất ngay.</p>
        </ConfirmDialog>
      )}
      <button type="button">After</button>
    </>
  );
}

function renderPage(over: Over = {}, startOpen = false, strict = false) {
  const tree = <Page over={over} startOpen={startOpen} />;
  return render(strict ? <StrictMode>{tree}</StrictMode> : tree);
}

const dialog = () => screen.getByRole("dialog");
const cancel = () => within(dialog()).getByRole("button", { name: S.admin.common.cancel });
const confirm = (name: string | RegExp = "Vô hiệu hoá") =>
  within(dialog()).getByRole("button", { name });

describe("the markup", () => {
  it("is a modal dialog named by its title", () => {
    renderPage({}, true);
    const box = dialog();
    expect(box).toHaveAttribute("aria-modal", "true");
    const labelledBy = box.getAttribute("aria-labelledby");
    expect(labelledBy).toBeTruthy();
    const title = document.getElementById(labelledBy ?? "");
    expect(title).toHaveTextContent("Vô hiệu hoá tuan.t1?");
    expect(screen.getByRole("dialog", { name: "Vô hiệu hoá tuan.t1?" })).toBe(box);
  });

  it("makes the title a heading and shows the children", () => {
    renderPage({}, true);
    expect(
      within(dialog()).getByRole("heading", { name: "Vô hiệu hoá tuan.t1?" }),
    ).toBeInTheDocument();
    expect(within(dialog()).getByText("Lê Tuấn bị đăng xuất ngay.")).toBeInTheDocument();
  });

  it("gives two dialogs two different title ids", () => {
    render(
      <>
        <ConfirmDialog title="Một" confirmLabel="OK" onConfirm={() => {}} onCancel={() => {}}>
          a
        </ConfirmDialog>
        <ConfirmDialog title="Hai" confirmLabel="OK" onConfirm={() => {}} onCancel={() => {}}>
          b
        </ConfirmDialog>
      </>,
    );
    const [one, two] = screen.getAllByRole("dialog");
    expect(one?.getAttribute("aria-labelledby")).not.toBe(two?.getAttribute("aria-labelledby"));
    expect(screen.getByRole("dialog", { name: "Một" })).toBe(one);
    expect(screen.getByRole("dialog", { name: "Hai" })).toBe(two);
  });

  it("says Huỷ on the cancel button unless it is given another word", () => {
    const first = renderPage({}, true);
    expect(cancel()).toHaveTextContent("Huỷ");
    first.unmount();
    renderPage({ cancelLabel: "Đóng" }, true);
    expect(within(dialog()).getByRole("button", { name: "Đóng" })).toBeInTheDocument();
    expect(within(dialog()).queryByRole("button", { name: "Huỷ" })).not.toBeInTheDocument();
  });

  it("renders a title and children as text, whatever they hold", () => {
    renderPage({ title: "<img src=x onerror=alert(1)>" }, true);
    expect(
      screen.getByRole("heading", { name: "<img src=x onerror=alert(1)>" }),
    ).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });
});

describe("the description", () => {
  it("is described by its body, so a screen reader reads what will happen", () => {
    renderPage({}, true);
    const id = dialog().getAttribute("aria-describedby");
    expect(id).toBeTruthy();
    const body = document.getElementById(id ?? "");
    expect(body).toContainElement(screen.getByText("Lê Tuấn bị đăng xuất ngay."));
    expect(dialog()).toHaveAccessibleDescription("Lê Tuấn bị đăng xuất ngay.");
  });

  it("is described by the body of each of two dialogs, not by the other's", () => {
    render(
      <>
        <ConfirmDialog title="Một" confirmLabel="OK" onConfirm={() => {}} onCancel={() => {}}>
          nội dung một
        </ConfirmDialog>
        <ConfirmDialog title="Hai" confirmLabel="OK" onConfirm={() => {}} onCancel={() => {}}>
          nội dung hai
        </ConfirmDialog>
      </>,
    );
    expect(screen.getByRole("dialog", { name: "Một" })).toHaveAccessibleDescription("nội dung một");
    expect(screen.getByRole("dialog", { name: "Hai" })).toHaveAccessibleDescription("nội dung hai");
  });

  it("has no aria-describedby, and no empty body, when there are no children", () => {
    render(
      <ConfirmDialog
        title="Chạy lại"
        confirmLabel="Chạy lại"
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    );
    expect(dialog()).not.toHaveAttribute("aria-describedby");
    expect(dialog()).toHaveAccessibleDescription("");
    expect(dialog().querySelector("[id]:not(h2)")).toBeNull();
  });

  it.each<[string, ReactNode]>([
    ["null", null],
    ["false", false],
    ["an empty text", ""],
  ])("has no aria-describedby for children that are %s", (_name, children) => {
    render(
      <ConfirmDialog
        title="Chạy lại"
        confirmLabel="Chạy lại"
        onConfirm={() => {}}
        onCancel={() => {}}
      >
        {children}
      </ConfirmDialog>,
    );
    expect(dialog()).not.toHaveAttribute("aria-describedby");
  });

  it("points at an element that exists, so axe finds no dangling reference", async () => {
    const { container } = render(
      <main>
        <Page startOpen />
      </main>,
    );
    const id = dialog().getAttribute("aria-describedby") ?? "";
    expect(document.getElementById(id)).not.toBeNull();
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("focus", () => {
  it("moves to the cancel button of a danger dialog on open", () => {
    renderPage({ tone: "danger" }, true);
    expect(cancel()).toHaveFocus();
  });

  it("moves to the confirm button of a primary dialog on open", () => {
    renderPage({ tone: "primary" }, true);
    expect(confirm()).toHaveFocus();
  });

  it("treats a dialog with no tone as primary", () => {
    renderPage({}, true);
    expect(confirm()).toHaveFocus();
  });

  it("moves in when the dialog is opened by a click, not only when it starts open", async () => {
    const user = userEvent.setup();
    renderPage({ tone: "danger" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Opener" }));
    expect(cancel()).toHaveFocus();
  });

  it("leaves the focus where a field of the children took it, such as an autoFocus input", () => {
    render(
      <ConfirmDialog
        title="Đặt lại"
        confirmLabel="Đặt lại"
        onConfirm={() => {}}
        onCancel={() => {}}
      >
        <label>
          Mật khẩu tạm
          <input type="password" autoFocus />
        </label>
      </ConfirmDialog>,
    );
    expect(screen.getByLabelText("Mật khẩu tạm")).toHaveFocus();
  });

  it.each([
    ["the cancel button", () => cancel()],
    ["the confirm button", () => confirm()],
  ])("returns to the opener when %s closes the dialog", async (_name, button) => {
    const user = userEvent.setup();
    renderPage({ tone: "danger" });
    const opener = screen.getByRole("button", { name: "Opener" });
    await user.click(opener);
    await user.click(button());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("returns to the opener when Esc closes the dialog", async () => {
    const user = userEvent.setup();
    renderPage({ tone: "danger" });
    const opener = screen.getByRole("button", { name: "Opener" });
    await user.click(opener);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("returns to the opener under StrictMode, whose effects run twice", async () => {
    const user = userEvent.setup();
    renderPage({ tone: "danger" }, false, true);
    const opener = screen.getByRole("button", { name: "Opener" });
    await user.click(opener);
    expect(cancel()).toHaveFocus();
    await user.click(cancel());
    expect(opener).toHaveFocus();
  });

  it("focuses nothing when the opener left the page while the dialog was open", async () => {
    const user = userEvent.setup();
    function Row() {
      const [shown, setShown] = useState(true);
      const [open, setOpen] = useState(false);
      return (
        <>
          {shown && (
            <button
              type="button"
              onClick={() => {
                setOpen(true);
                setShown(false);
              }}
            >
              Row action
            </button>
          )}
          {open && (
            <ConfirmDialog
              title="Kích hoạt lại?"
              confirmLabel="Kích hoạt"
              onConfirm={() => setOpen(false)}
              onCancel={() => setOpen(false)}
            >
              x
            </ConfirmDialog>
          )}
        </>
      );
    }
    render(<Row />);
    await user.click(screen.getByRole("button", { name: "Row action" }));
    await user.click(within(dialog()).getByRole("button", { name: "Huỷ" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(document.body).toHaveFocus();
  });
});

describe("the Tab trap", () => {
  it("takes Tab from the last button to the first, and not to the page behind", async () => {
    const user = userEvent.setup();
    renderPage({ tone: "danger" }, true);
    expect(cancel()).toHaveFocus();
    await user.tab();
    expect(confirm()).toHaveFocus();
    await user.tab();
    expect(cancel()).toHaveFocus();
    expect(screen.getByRole("button", { name: "After" })).not.toHaveFocus();
  });

  it("takes Shift+Tab from the first button to the last, and not to the page behind", async () => {
    const user = userEvent.setup();
    renderPage({ tone: "danger" }, true);
    expect(cancel()).toHaveFocus();
    await user.tab({ shift: true });
    expect(confirm()).toHaveFocus();
    await user.tab({ shift: true });
    expect(cancel()).toHaveFocus();
    expect(screen.getByRole("button", { name: "Before" })).not.toHaveFocus();
  });

  it("cycles through the fields of the children too, in the order of the page", async () => {
    const user = userEvent.setup();
    render(
      <>
        <button type="button">Before</button>
        <ConfirmDialog
          title="Đặt lại"
          confirmLabel="Đặt lại"
          onConfirm={() => {}}
          onCancel={() => {}}
        >
          <input aria-label="Mật khẩu tạm" />
          <input aria-label="Nhập lại" />
        </ConfirmDialog>
        <button type="button">After</button>
      </>,
    );
    const order = [
      screen.getByLabelText("Mật khẩu tạm"),
      screen.getByLabelText("Nhập lại"),
      screen.getByRole("button", { name: "Huỷ" }),
      screen.getByRole("button", { name: "Đặt lại" }),
    ];
    // The confirm button has the focus on open (primary); Tab wraps to the first field.
    expect(order[3]).toHaveFocus();
    for (const next of [order[0], order[1], order[2], order[3], order[0]]) {
      await user.tab();
      expect(next).toHaveFocus();
    }
    await user.tab({ shift: true });
    expect(order[3]).toHaveFocus();
  });

  it("brings Tab back inside when the focus was lost to the page", async () => {
    const user = userEvent.setup();
    renderPage({ tone: "danger" }, true);
    screen.getByRole("button", { name: "After" }).focus();
    await user.tab();
    expect(dialog().contains(document.activeElement)).toBe(true);
  });

  it("keeps the focus in the dialog when there is nothing in it to focus", async () => {
    const user = userEvent.setup();
    renderPage({ busy: true }, true);
    await user.tab();
    expect(dialog().contains(document.activeElement)).toBe(true);
    await user.tab({ shift: true });
    expect(dialog().contains(document.activeElement)).toBe(true);
  });
});

describe("Esc", () => {
  it("cancels", async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();
    renderPage({ onCancel }, true);
    await user.keyboard("{Escape}");
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("cancels from a field of the children too", async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();
    render(
      <ConfirmDialog title="t" confirmLabel="OK" onConfirm={() => {}} onCancel={onCancel}>
        <input aria-label="field" autoFocus />
      </ConfirmDialog>,
    );
    await user.keyboard("{Escape}");
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("does not cancel while the dialog is busy", async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();
    renderPage({ onCancel, busy: true }, true);
    await user.keyboard("{Escape}");
    expect(onCancel).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("cancels again once the dialog is no longer busy", async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();
    const view = render(
      <ConfirmDialog title="t" confirmLabel="OK" busy onConfirm={() => {}} onCancel={onCancel}>
        x
      </ConfirmDialog>,
    );
    await user.keyboard("{Escape}");
    expect(onCancel).not.toHaveBeenCalled();
    view.rerender(
      <ConfirmDialog title="t" confirmLabel="OK" onConfirm={() => {}} onCancel={onCancel}>
        x
      </ConfirmDialog>,
    );
    await user.keyboard("{Escape}");
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("stops listening when the dialog is gone", async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();
    const view = renderPage({ onCancel }, true);
    view.unmount();
    await user.keyboard("{Escape}");
    expect(onCancel).not.toHaveBeenCalled();
  });
});

describe("the buttons", () => {
  it("calls onConfirm when the confirm button is pressed, and onCancel for Huỷ", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    renderPage({ onConfirm, onCancel }, true);
    await user.click(confirm());
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onCancel).not.toHaveBeenCalled();
    await user.click(cancel());
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("does not cancel when the overlay behind the dialog is clicked", async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();
    renderPage({ onCancel }, true);
    const overlay = dialog().parentElement;
    expect(overlay).not.toBeNull();
    await user.click(overlay as HTMLElement);
    expect(onCancel).not.toHaveBeenCalled();
  });

  it("is in the tab order as cancel first, then confirm", () => {
    renderPage({}, true);
    const buttons = within(dialog()).getAllByRole("button");
    expect(buttons.map((b) => b.textContent)).toEqual(["Huỷ", "Vô hiệu hoá"]);
  });

  it("styles a danger confirm apart from a primary one", () => {
    const danger = renderPage({ tone: "danger" }, true);
    const dangerClass = confirm().className;
    danger.unmount();
    renderPage({ tone: "primary" }, true);
    expect(confirm().className).not.toBe(dangerClass);
  });
});

describe("while busy", () => {
  it("disables the confirm button and shows the busy state", () => {
    renderPage({ busy: true }, true);
    const busy = within(dialog()).getByRole("button", { name: S.admin.common.working });
    expect(busy).toBeDisabled();
    expect(busy).toHaveAttribute("aria-busy", "true");
    expect(within(dialog()).queryByRole("button", { name: "Vô hiệu hoá" })).not.toBeInTheDocument();
  });

  it("does not call onConfirm for a press on the disabled button", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    renderPage({ busy: true, onConfirm }, true);
    await user.click(within(dialog()).getByRole("button", { name: S.admin.common.working }));
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("disables the cancel button too, so a write in flight cannot be called off", async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();
    renderPage({ busy: true, onCancel }, true);
    expect(cancel()).toBeDisabled();
    await user.click(cancel());
    expect(onCancel).not.toHaveBeenCalled();
  });

  it("is not marked busy, and has its own label, when it is idle", () => {
    renderPage({}, true);
    expect(confirm()).toBeEnabled();
    expect(confirm()).not.toHaveAttribute("aria-busy");
  });
});

describe("the two optional switches", () => {
  it("confirmDisabled disables the confirm button and nothing else", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    renderPage({ confirmDisabled: true, onConfirm, tone: "primary" }, true);
    expect(confirm()).toBeDisabled();
    expect(cancel()).toBeEnabled();
    // A disabled confirm cannot take the focus a primary dialog gives it: the cancel button does.
    expect(cancel()).toHaveFocus();
    await user.click(confirm());
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("hideConfirm leaves the cancel button alone, for a refusal that has nothing to confirm", () => {
    renderPage({ hideConfirm: true, cancelLabel: "Đóng", tone: "primary" }, true);
    expect(
      within(dialog())
        .getAllByRole("button")
        .map((b) => b.textContent),
    ).toEqual(["Đóng"]);
    expect(within(dialog()).getByRole("button", { name: "Đóng" })).toHaveFocus();
  });
});

describe("the error", () => {
  it("shows a text inside the dialog with role=alert", () => {
    renderPage({ error: "Không thể vô hiệu hoá admin hoạt động cuối cùng." }, true);
    const alert = within(dialog()).getByRole("alert");
    expect(alert).toHaveTextContent("Không thể vô hiệu hoá admin hoạt động cuối cùng.");
  });

  it("shows a node inside the dialog with role=alert", () => {
    renderPage(
      {
        error: (
          <span>
            lỗi <b>409</b>
          </span>
        ),
      },
      true,
    );
    const alert = within(dialog()).getByRole("alert");
    expect(within(alert).getByText("409")).toBeInTheDocument();
  });

  it.each<[string, Over["error"]]>([
    ["undefined", undefined],
    ["null", null],
    ["an empty text", ""],
    ["false", false],
  ])("shows no alert for %s", (_name, error) => {
    renderPage({ error }, true);
    expect(within(dialog()).queryByRole("alert")).not.toBeInTheDocument();
  });

  it("renders an error text as text", () => {
    renderPage({ error: "<b>x</b>" }, true);
    expect(within(dialog()).getByRole("alert")).toHaveTextContent("<b>x</b>");
    expect(dialog().querySelector("b")).toBeNull();
  });

  it("keeps the buttons usable, so the admin can try again or give up", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    renderPage({ error: "Mất kết nối", onConfirm }, true);
    await user.click(confirm());
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});

describe("accessibility", () => {
  async function violations(container: HTMLElement) {
    // jsdom computes no layout or colour, so the contrast rule cannot run here.
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    return result.violations.map((v) => v.id);
  }

  it.each<[string, Over]>([
    ["a danger dialog", { tone: "danger" }],
    ["a primary dialog", { tone: "primary" }],
    ["a busy dialog", { busy: true }],
    ["a dialog with an error", { error: "Mất kết nối máy chủ" }],
    ["a refusal with one button", { hideConfirm: true, cancelLabel: "Đóng", error: "Không thể" }],
  ])("has no axe violation for %s", async (_name, over) => {
    const { container } = render(
      <main>
        <Page over={over} startOpen />
      </main>,
    );
    expect(await violations(container)).toEqual([]);
  });

  it("has no axe violation with a labelled field inside", async () => {
    const field: ReactNode = (
      <label>
        Mật khẩu tạm
        <input type="password" />
      </label>
    );
    const { container } = render(
      <main>
        <ConfirmDialog
          title="Đặt lại mật khẩu"
          confirmLabel="Đặt lại"
          onConfirm={() => {}}
          onCancel={() => {}}
        >
          {field}
        </ConfirmDialog>
      </main>,
    );
    expect(await violations(container)).toEqual([]);
  });
});
