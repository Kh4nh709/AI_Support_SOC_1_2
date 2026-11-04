// src/features/admin/LabRunRace.test.tsx — P14-T10 fix round 1, item I1 (the independent review's finding).
//
// A read of the run's alerts that is already out when a label write succeeds must not bring back the snapshot it took
// before the write. The run page sets the label and the counter in the cache of an infinite query; a refetch of that
// query (a window focus, a reconnect, the run opened again within the cache lifetime) re-reads every page it has
// loaded, one after the other, and if one is on its way when the write lands, its answer used to overwrite the cache
// with the state the server no longer held: the row and "Đã gán x/y" went back, and the next labels moved the counter
// from the wrong number.
//
// The scenario is the reviewer's: two pages loaded, a refetch started with page 2 held back by the server, a label on
// a row of page 1 (a TP, and then a "Bỏ nhãn"), and the refetch released. What the row and the counter show must be
// what the server holds. A focus of the window must not start such a refetch at all.
import { QueryClient, QueryClientProvider, focusManager } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter, Route, Routes } from "react-router";
import type { LabAlert, LabLabel } from "../../api/admin";
import { adminKeys } from "./adminKeys";
import { LabRunPage } from "./LabRunPage";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  focusManager.setFocused(undefined);
});
afterAll(() => server.close());

const RUN_ID = "5f1c0a2e-3b4d-4e5f-8a9b-0123456789ab";
const alert = (n: number, label: LabLabel | null): LabAlert => ({
  alert_id: `1766000000.${n}`,
  received_at: `2026-11-04T02:0${n}:00Z`,
  alert_time: `2026-11-04T01:5${n}:30Z`,
  rule_id: `9900${n}`,
  rule_level: 5,
  severity: "medium",
  description: `alert ${n}`,
  agent_name: `host-${n}`,
  alert_user: null,
  srcip: "",
  dstip: "",
  category: "c",
  mitre_ids: [],
  occurrence_count: 1,
  raw_log: "",
  raw_log_truncated_for_display: false,
  label,
});

/** Three alerts in pages of two. A request for page 2 can be held: the server has read the labels, and answers later. */
function backend() {
  const alerts = [alert(1, "true_positive"), alert(2, null), alert(3, null)];
  const pageSize = 2;
  let hold: Promise<void> | null = null;
  let release: () => void = () => {};
  let heldArrived = false;
  let gets = 0;
  server.use(
    http.get("/api/admin/lab/runs/:runId/alerts", async ({ request }) => {
      gets += 1;
      const after = new URL(request.url).searchParams.get("after");
      // The server computes the answer when the request arrives: a snapshot of the labels at that moment.
      const from = after === null ? 0 : alerts.findIndex((a) => a.alert_id === after) + 1;
      const page = alerts.slice(from, from + pageSize).map((a) => ({ ...a }));
      const run = {
        run_id: RUN_ID,
        name: "run",
        purpose: "test",
        starts_at: "2026-11-04T02:00:00Z",
        ends_at: "2026-11-04T04:00:00Z",
        total: alerts.length,
        labelled: alerts.filter((a) => a.label !== null).length,
      };
      const body = {
        run,
        alerts: page,
        next_after: page.length === pageSize ? (page[page.length - 1]?.alert_id ?? null) : null,
      };
      if (after !== null && hold !== null) {
        heldArrived = true;
        await hold;
      }
      return HttpResponse.json(body);
    }),
    http.put("/api/admin/lab/labels/:alertId", async ({ request, params }) => {
      const { label } = (await request.json()) as { label: LabLabel };
      const found = alerts.find((a) => a.alert_id === String(params.alertId));
      if (found) found.label = label;
      return HttpResponse.json({ alert_id: params.alertId, run_id: RUN_ID, label });
    }),
    http.delete("/api/admin/lab/labels/:alertId", ({ params }) => {
      const found = alerts.find((a) => a.alert_id === String(params.alertId));
      if (found) found.label = null;
      return new HttpResponse(null, { status: 204 });
    }),
  );
  return {
    alerts,
    gets: () => gets,
    holdLaterPages: () => {
      hold = new Promise<void>((resolve) => {
        release = resolve;
      });
    },
    heldArrived: () => heldArrived,
    release: () => release(),
  };
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/admin/lab/${RUN_ID}`]}>
        <main>
          <Routes>
            <Route path="/admin/lab/:runId" element={<LabRunPage />} />
          </Routes>
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

const rowOf = async (n: number) =>
  within(await screen.findByRole("listitem", { name: `Alert 1766000000.${n}` }));
const chip = (row: ReturnType<typeof within>) => row.getByText(/^(TP|FP|chưa gán)$/);
const counter = () => screen.getByText(/^Đã gán \d+\/\d+$/).textContent;

async function twoPagesLoaded(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText("Đã gán 1/3");
  await user.click(await screen.findByRole("button", { name: "Tải thêm" }));
  await rowOf(3);
}

/**
 * A refetch of the run's pages, with page 2 held back by the server. It is started as the app's own triggers do (a
 * mount of a cached run, a reconnect): `refetchQueries` on the run's key.
 */
async function refetchWithPage2Held(client: QueryClient, b: ReturnType<typeof backend>) {
  b.holdLaterPages();
  // (not awaited: the refetch stays out until the server is let go)
  await act(async () => {
    void client.refetchQueries({ queryKey: adminKeys.labRun(RUN_ID) });
  });
  await waitFor(() => expect(b.heldArrived()).toBe(true));
}

/** Lets the held answer reach the page, and waits until nothing of the run is being read. */
async function releaseAndSettle(client: QueryClient, b: ReturnType<typeof backend>) {
  b.release();
  await waitFor(() => expect(client.isFetching()).toBe(0));
}

describe("a read of the run that is out when a label write succeeds", () => {
  it("does not take a TP off the row, nor the counter back, when it lands", async () => {
    const b = backend();
    const user = userEvent.setup();
    const client = renderPage();
    await twoPagesLoaded(user);
    await refetchWithPage2Held(client, b);

    // The admin labels alert 2 (page 1) TP while page 2 of the refetch is still out.
    const two = await rowOf(2);
    await user.click(two.getByRole("button", { name: "TP — tấn công thật" }));
    await screen.findByText("Đã gán 2/3");
    expect(chip(two)).toHaveTextContent("TP");
    expect(b.alerts[1]?.label).toBe("true_positive"); // the server holds TP

    await releaseAndSettle(client, b);

    expect({ row: chip(await rowOf(2)).textContent, counter: counter() }).toEqual({
      row: "TP",
      counter: "Đã gán 2/3",
    });
  });

  it("does not put a label back on the row, nor the counter, after `Bỏ nhãn`, when it lands", async () => {
    const b = backend();
    const user = userEvent.setup();
    const client = renderPage();
    await twoPagesLoaded(user);
    await refetchWithPage2Held(client, b);

    const one = await rowOf(1);
    await user.click(one.getByRole("button", { name: "Bỏ nhãn" }));
    await screen.findByText("Đã gán 0/3");
    expect(b.alerts[0]?.label).toBeNull(); // the server holds no label

    await releaseAndSettle(client, b);

    expect({ row: chip(await rowOf(1)).textContent, counter: counter() }).toEqual({
      row: "chưa gán",
      counter: "Đã gán 0/3",
    });
  });

  it("moves the counter from the right number on the labels that follow", async () => {
    const b = backend();
    const user = userEvent.setup();
    const client = renderPage();
    await twoPagesLoaded(user);
    await refetchWithPage2Held(client, b);
    await user.click((await rowOf(2)).getByRole("button", { name: "TP — tấn công thật" }));
    await screen.findByText("Đã gán 2/3");
    await releaseAndSettle(client, b);

    await user.click((await rowOf(3)).getByRole("button", { name: "FP — không phải tấn công" }));
    expect(await screen.findByText("Đã gán 3/3")).toBeInTheDocument();
    expect(b.alerts.map((a) => a.label)).toEqual([
      "true_positive",
      "true_positive",
      "false_positive",
    ]);
  });
});

// P14 final fix wave, item 42. `labelled` cancels the read that is out so that its old snapshot cannot undo the write;
// the cancelled read's news (another admin's label, an alert that arrived) went with it, and nothing read again. When
// the read it cancelled was a refetch of the loaded pages, the run is read once more after the write, so that read comes
// after it. A cancelled "Tải thêm" is not a refetch: its press is simply repeated, and nothing is read in its place.
describe("a refetch that a label write cancelled", () => {
  it("is read again after the write, so the news it carried is not lost", async () => {
    const b = backend();
    const user = userEvent.setup();
    const client = renderPage();
    await twoPagesLoaded(user);
    await refetchWithPage2Held(client, b);
    const getsBefore = b.gets();

    // While that refetch is out another admin labels alert 3 FP (the refetch took its snapshot before): its answer
    // cannot carry that, and it is cancelled by the write below.
    const third = b.alerts[2];
    if (third) third.label = "false_positive";
    const two = await rowOf(2);
    await user.click(two.getByRole("button", { name: "TP — tấn công thật" }));
    await screen.findByText(/^Đã gán \d+\/3$/);
    expect(b.alerts[1]?.label).toBe("true_positive");

    await releaseAndSettle(client, b);

    // the page read the run again after the write: the news is there, and the counter is the server's
    await waitFor(async () => expect(chip(await rowOf(3))).toHaveTextContent("FP"));
    expect({ two: chip(await rowOf(2)).textContent, counter: counter() }).toEqual({
      two: "TP",
      counter: "Đã gán 3/3",
    });
    expect(b.gets()).toBeGreaterThan(getsBefore);
  });

  it("is not read again when what the write cancelled was a `Tải thêm` (its press is repeated instead)", async () => {
    const b = backend();
    const user = userEvent.setup();
    const client = renderPage();
    await screen.findByText("Đã gán 1/3");
    b.holdLaterPages();
    // not awaited: the next page stays out until the server is let go
    await user.click(await screen.findByRole("button", { name: "Tải thêm" }));
    await waitFor(() => expect(b.heldArrived()).toBe(true));
    const getsBefore = b.gets();

    await user.click((await rowOf(2)).getByRole("button", { name: "TP — tấn công thật" }));
    await screen.findByText("Đã gán 2/3");
    b.release();
    await waitFor(() => expect(client.isFetching()).toBe(0));

    expect(b.gets()).toBe(getsBefore); // no read in place of the cancelled page
    expect(counter()).toBe("Đã gán 2/3");
    expect(screen.queryByRole("listitem", { name: "Alert 1766000000.3" })).not.toBeInTheDocument();
    // the cancelled press is pressed again, as before
    await user.click(await screen.findByRole("button", { name: "Tải thêm" }));
    await rowOf(3);
    expect(counter()).toBe("Đã gán 2/3");
  });
});

describe("a focus of the window", () => {
  it("does not read the loaded pages again: a label is not undone by a focus, and a large run is not reloaded", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await twoPagesLoaded(user);
    const before = b.gets();
    expect(before).toBe(2);

    act(() => {
      focusManager.setFocused(false);
      focusManager.setFocused(true);
    });
    await new Promise((resolve) => setTimeout(resolve, 150));

    expect(b.gets()).toBe(before);
  });
});
