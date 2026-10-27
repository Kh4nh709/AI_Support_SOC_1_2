// src/features/tier1/SoarSections.test.tsx — the SOAR enrichment sections of the alert page (S3): the TheHive
// case, the planned action, the scenario and its triage, the history, the GEO01 block, the SC03 scan and the
// TI lookups. Each shows only when `view.soar` carries its data. Every value is untrusted SIEM text, so the
// tests below feed hostile strings and look for any element they could have made.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { cleanup, render, screen, within } from "@testing-library/react";
import axe from "axe-core";
import type { AlertView, SoarBlob } from "../../api/tier1";
import { S } from "../../strings";
import { FILTERLOG, GEO, MW03, PORTS, SC03 } from "./soarFixtures";
import {
  PORTS_SHOWN,
  SoarAction,
  SoarCase,
  SoarGeo,
  SoarHistory,
  SoarScan,
  SoarScenario,
  SoarTi,
} from "./SoarSections";

const view = (soar: SoarBlob | null | undefined): AlertView => ({
  alert_id: "a1",
  status: "queued_tier1",
  suggestion_visible: true,
  soar,
});

const h3 = (name: string) => screen.queryByRole("heading", { level: 3, name });
const valueOf = (label: string) => screen.getByText(label, { selector: "dt" }).nextElementSibling;

const ALL = [SoarCase, SoarAction, SoarScenario, SoarHistory, SoarGeo, SoarScan, SoarTi] as const;

const NONE: [string, SoarBlob | null | undefined][] = [
  ["soar is null", null],
  ["soar is absent", undefined],
  ["soar is empty", {}],
  ["every block is empty", { case: {}, action: {}, scenario: {}, history: {}, geo: {}, ti: [] }],
];

describe("with no SOAR data", () => {
  it.each(NONE)("shows no section when %s", (_name, soar) => {
    for (const Section of ALL) {
      const { container, unmount } = render(<Section view={view(soar)} />);
      expect(container).toBeEmptyDOMElement();
      unmount();
    }
  });

  it("shows only the sections whose data is there", () => {
    render(
      <>
        {ALL.map((Section, i) => (
          <Section key={i} view={view(MW03)} />
        ))}
      </>,
    );
    expect(h3(S.alert.soar.caseTitle)).toBeInTheDocument();
    expect(h3(S.alert.soar.actionTitle)).toBeInTheDocument();
    expect(h3(S.alert.soar.scenarioTitle)).toBeInTheDocument();
    expect(h3(S.alert.soar.historyTitle)).toBeInTheDocument();
    // MW03 carries no geo, no scan and no TI.
    expect(h3(S.alert.soar.geoTitle)).toBeNull();
    expect(h3(S.alert.soar.scanTitle)).toBeNull();
    expect(h3(S.alert.soar.tiTitle)).toBeNull();
  });
});

describe("the TheHive case", () => {
  it("says the case number and keeps the dedup key and the TheHive alert id as secondary", () => {
    render(<SoarCase view={view(MW03)} />);
    expect(screen.getByText("Case TheHive: #50")).toBeInTheDocument();
    expect(S.alert.soar.caseNumber(50)).toBe("Case TheHive: #50");
    expect(valueOf(S.alert.soar.dedupKey)).toHaveTextContent(MW03.case!.dedup_key!);
    expect(valueOf(S.alert.soar.thehiveAlertId)).toHaveTextContent("~921656");
    // It is text: the page links to no TheHive (a base URL is a follow-up, never hard-coded).
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("says no case was made when the number is null (a low SOAR score)", () => {
    render(<SoarCase view={view({ case: { ...MW03.case, case_number: null } })} />);
    expect(screen.getByText("chưa tạo case (điểm thấp)")).toBeInTheDocument();
    expect(S.alert.soar.noCase).toBe("chưa tạo case (điểm thấp)");
    expect(screen.queryByText(/#/)).toBeNull();
    expect(valueOf(S.alert.soar.dedupKey)).toHaveTextContent("MW03|");
  });

  it("is not the internal Tier-2 case: it never says 'Case' alone or links to /cases", () => {
    const { container } = render(<SoarCase view={view(SC03)} />);
    expect(container.querySelector("a")).toBeNull();
    expect(screen.getByText("Case TheHive: #55")).toBeInTheDocument();
  });
});

describe("the planned action", () => {
  it.each([
    [MW03, "none → Windows_Endpoint (approval, act_first)"],
    [SC03, "block_ip → 79.79.78.202 (auto, act_first)"],
  ])("writes type → target (tier, mode)", (soar, text) => {
    render(<SoarAction view={view(soar)} />);
    expect(screen.getByText(text)).toBeInTheDocument();
  });

  it("leaves out what it was not given", () => {
    render(<SoarAction view={view({ action: { type: "block_ip" } })} />);
    expect(screen.getByText("block_ip")).toBeInTheDocument();
    cleanup();
    render(<SoarAction view={view({ action: { type: "block_ip", target: "1.2.3.4" } })} />);
    expect(screen.getByText("block_ip → 1.2.3.4")).toBeInTheDocument();
  });
});

describe("the scenario and its triage", () => {
  it("shows the scenario, the SIEM score, the signal and its codes, as the SIEM's own", () => {
    render(<SoarScenario view={view(SC03)} />);
    expect(valueOf(S.alert.soar.scenario)).toHaveTextContent("SC03 — External port scan (pfSense)");
    expect(valueOf(S.alert.soar.score)).toHaveTextContent("50");
    expect(valueOf(S.alert.soar.signal)).toHaveTextContent(SC03.triage!.signal_text!);
    expect(valueOf(S.alert.soar.signalCodes)).toHaveTextContent("external_port_scan");
    // display only: the section says so
    expect(screen.getByText(S.alert.soar.scoreHint)).toBeInTheDocument();
  });

  it("shows a score of 0", () => {
    render(<SoarScenario view={view({ triage: { score: 0 } })} />);
    expect(valueOf(S.alert.soar.score)).toHaveTextContent("0");
  });
});

describe("the history", () => {
  it("shows the counts, whether this host is new, and the last time in +07", () => {
    render(<SoarHistory view={view(SC03)} />);
    expect(valueOf(S.alert.soar.ruleTotal7d)).toHaveTextContent("4");
    expect(valueOf(S.alert.soar.ruleHost7d)).toHaveTextContent("4");
    expect(valueOf(S.alert.soar.ruleHosts7d)).toHaveTextContent("1");
    expect(valueOf(S.alert.soar.firstSeenHost)).toHaveTextContent("Không");
    // 18:13:31Z, in Asia/Ho_Chi_Minh, under TZ=UTC: the next day, 01:13
    expect(valueOf(S.alert.soar.lastSeen)).toHaveTextContent("17/10/2026 01:13:31");
  });

  it("shows zeros and a first sighting for MW03, with no last-seen row", () => {
    render(<SoarHistory view={view(MW03)} />);
    expect(valueOf(S.alert.soar.ruleTotal7d)).toHaveTextContent("0");
    expect(valueOf(S.alert.soar.firstSeenHost)).toHaveTextContent("Có");
    expect(screen.queryByText(S.alert.soar.lastSeen, { selector: "dt" })).toBeNull();
  });
});

describe("the GEO01 block", () => {
  it("shows each field it was given, the country with 'mô phỏng' when simulated", () => {
    render(<SoarGeo view={view(GEO)} />);
    expect(valueOf(S.alert.soar.country)).toHaveTextContent("VN (mô phỏng)");
    expect(valueOf(S.alert.soar.srcIpType)).toHaveTextContent("external");
    expect(valueOf(S.alert.soar.firstSeenCountry30d)).toHaveTextContent("Có");
    expect(valueOf(S.alert.soar.seenCount30d)).toHaveTextContent("3");
    expect(valueOf(S.alert.soar.priorFailures30m)).toHaveTextContent("12");
    expect(valueOf(S.alert.soar.impossibleTravel)).toHaveTextContent("Không");
    expect(valueOf(S.alert.soar.offHours)).toHaveTextContent("Có");
  });

  it("is present-only, field by field", () => {
    render(<SoarGeo view={view({ geo: { country: "US", seen_count_30d: 0 } })} />);
    expect(valueOf(S.alert.soar.country)).toHaveTextContent("US");
    expect(valueOf(S.alert.soar.country)).not.toHaveTextContent(S.alert.soar.simulated);
    expect(valueOf(S.alert.soar.seenCount30d)).toHaveTextContent("0");
    expect(screen.queryByText(S.alert.soar.offHours, { selector: "dt" })).toBeNull();
    expect(screen.queryByText(S.alert.soar.impossibleTravel, { selector: "dt" })).toBeNull();
  });
});

describe("the SC03 scan", () => {
  it("shows the counters, a bounded sample of ports, the targets and the actions", () => {
    render(<SoarScan view={view(SC03)} />);
    expect(valueOf(S.alert.soar.sampledPackets)).toHaveTextContent("300");
    expect(valueOf(S.alert.soar.distinctPorts)).toHaveTextContent("180");
    expect(valueOf(S.alert.soar.dstIps)).toHaveTextContent("79.79.78.75");
    expect(valueOf(S.alert.soar.scanActions)).toHaveTextContent("block");
    const ports = valueOf(S.alert.soar.portsSample)!;
    expect(ports).toHaveTextContent(PORTS.slice(0, PORTS_SHOWN).join(", "));
    expect(ports).not.toHaveTextContent(PORTS[PORTS_SHOWN]!);
    expect(ports).toHaveTextContent(S.alert.soar.morePorts(50 - PORTS_SHOWN));
  });

  it("keeps the filterlog lines collapsed, as one text node, with a copy button", () => {
    const { container } = render(<SoarScan view={view(SC03)} />);
    const details = container.querySelector("details")!;
    expect(details).not.toBeNull();
    expect(details.open).toBe(false);
    expect(within(details).getByText(S.alert.soar.previousOutput, { selector: "summary" })).toBe(
      details.querySelector("summary"),
    );
    const log = screen.getByRole("region", { name: S.alert.soar.previousOutput, hidden: true });
    expect(log.tagName).toBe("PRE");
    expect(log.textContent).toBe(SC03.scan!.previous_output);
    expect(log.childNodes).toHaveLength(1);
  });

  it("says when the server cut the lines", () => {
    const cut: SoarBlob = {
      scan: {
        previous_output: FILTERLOG,
        previous_output_truncated: true,
        previous_output_lines: 300,
      },
    };
    render(<SoarScan view={view(cut)} />);
    expect(screen.getByText(S.alert.rawLogTruncated, { exact: false })).toBeInTheDocument();
    expect(
      screen.getByText(S.alert.soar.previousOutputLines(300), { selector: "summary" }),
    ).toBeInTheDocument();
  });

  it("shows no ports row when the sample is empty and no details when there are no lines", () => {
    const { container } = render(
      <SoarScan view={view({ scan: { sampled_packets: 10, ports_sampled: [] } })} />,
    );
    expect(screen.queryByText(S.alert.soar.portsSample, { selector: "dt" })).toBeNull();
    expect(container.querySelector("details")).toBeNull();
    expect(valueOf(S.alert.soar.sampledPackets)).toHaveTextContent("10");
  });
});

describe("the TI lookups", () => {
  it("lists each entry as type, value and verdict", () => {
    render(<SoarTi view={view(SC03)} />);
    expect(h3(S.alert.soar.tiTitle)).toBeInTheDocument();
    expect(screen.getByText("ip · 79.79.78.202 · clean")).toBeInTheDocument();
  });
});

const HOSTILE = '<img src=x onerror="window.__s3=1"></script><script>window.__s3=2</script>';

/** A blob whose every SOAR text field is hostile. */
const HOSTILE_BLOB: SoarBlob = {
  case: { case_number: HOSTILE, thehive_alert_id: HOSTILE, dedup_key: HOSTILE, case_id: HOSTILE },
  action: { type: HOSTILE, target: HOSTILE, tier: HOSTILE, mode: HOSTILE },
  scenario: { id: HOSTILE, name: HOSTILE },
  triage: { score: 1, signal_text: HOSTILE, signal_codes: [HOSTILE] },
  history: { last_seen: HOSTILE },
  geo: { country: HOSTILE, src_ip_type: HOSTILE },
  scan: {
    ports_sampled: [HOSTILE],
    dst_ips: [HOSTILE],
    actions: [HOSTILE],
    previous_output: `${HOSTILE}\n${HOSTILE}`,
  },
  ti: [{ type: HOSTILE, value: HOSTILE, verdict: HOSTILE }],
};

describe("hostile SIEM text (Review Focus 1)", () => {
  it("renders every SOAR field as text: no element is made from it, nothing runs", () => {
    const { container } = render(
      <>
        {ALL.map((Section, i) => (
          <Section key={i} view={view(HOSTILE_BLOB)} />
        ))}
      </>,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("[onerror]")).toBeNull();
    expect((window as unknown as { __s3?: number }).__s3).toBeUndefined();
    // and it is there, literally, in the places a reader looks
    expect(container.textContent).toContain(HOSTILE);
    const log = screen.getByRole("region", { name: S.alert.soar.previousOutput, hidden: true });
    expect(log.textContent).toBe(`${HOSTILE}\n${HOSTILE}`);
    expect(screen.getByText(`Case TheHive: #${HOSTILE}`)).toBeInTheDocument();
  });

  it("is the same handful of elements for a 100 KB line as for a short one", () => {
    const sections = (text: string) => (
      <>
        {ALL.map((Section, i) => (
          <Section
            key={i}
            view={view({
              ...SC03,
              triage: { score: 1, signal_text: text },
              scan: { ...SC03.scan, previous_output: text },
            })}
          />
        ))}
      </>
    );
    const small = render(sections("short"));
    const smallCount = small.container.querySelectorAll("*").length;
    small.unmount();
    const large = render(sections("x".repeat(100_000)));
    expect(large.container.querySelectorAll("*").length).toBe(smallCount);
  });
});

describe("accessibility", () => {
  const blobs: [string, SoarBlob][] = [
    ["MW03", MW03],
    ["SC03", SC03],
    ["GEO01", { ...MW03, ...GEO }],
    ["hostile", HOSTILE_BLOB],
  ];

  it.each(blobs)("has no axe violation: %s", async (_name, soar) => {
    render(
      <main>
        <h1>{S.alert.infoHeading}</h1>
        <h2>{S.alert.infoHeading}</h2>
        {ALL.map((Section, i) => (
          <Section key={i} view={view(soar)} />
        ))}
      </main>,
    );
    // jsdom computes no colour, so the contrast rule cannot run here.
    const result = await axe.run(document.body, {
      rules: { "color-contrast": { enabled: false } },
    });
    expect(
      result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`),
    ).toEqual([]);
  });
});

describe("the copy", () => {
  it("is all in strings.ts: the component writes no Vietnamese of its own", () => {
    const source = readFileSync(join("src", "features", "tier1", "SoarSections.tsx"), "utf8");
    const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
    expect(code.match(/[^\t\n\r -~]/g) ?? []).toEqual([]);
  });
});
