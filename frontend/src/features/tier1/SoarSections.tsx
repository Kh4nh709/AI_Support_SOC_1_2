// The SOAR enrichment of the alert page (S3): what the SIEM's SOAR team added to the alert and the page shows
// in the left column, next to the Wazuh fields: the TheHive case, the planned action, the scenario and its
// triage, the history, the GEO01 block, the SC03 scan and the TI lookups. Each block shows only when
// `view.soar` carries its data, field by field, so an alert the SIEM did not enrich is a page without them.
//
// Every value here is the SIEM's free text and is rendered as a React text node, never as markup: a
// signal text, a dedup key or a filterlog line holding `<img onerror=...>` or `</script>` is characters on
// the screen. The values are also checked for their type before they are drawn, so a server that sent an
// object where a text was expected shows nothing for it instead of failing the page. The SIEM's score and
// signal are displayed, never used: nothing here (or in the ① column) reads them into a decision. All the
// words are in `strings.ts`.
import type { ReactNode } from "react";
import type { AlertView, SoarGeoValue } from "../../api/tier1";
import { KeyValueGrid, visibleItems, type KeyValueItem } from "../../components/KeyValueGrid";
import { LogBlock } from "../../components/LogBlock";
import { formatDateTime } from "../../format";
import { S } from "../../strings";
import { Block } from "./AlertSections";

/** How many of the sampled destination ports the scan block lists; the rest are counted. */
export const PORTS_SHOWN = 20;

const text = (value: unknown): string =>
  typeof value === "string" ? value : typeof value === "number" ? String(value) : "";

const num = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

const list = (value: unknown): string[] =>
  Array.isArray(value) ? value.map(text).filter((item) => item !== "") : [];

const yesNo = (value: unknown): string | null =>
  value === true ? S.alert.soar.yes : value === false ? S.alert.soar.no : null;

/** A GEO01 value in words: a flag as yes or no, a number or a text as it is, anything else as nothing. */
const geoValue = (value: SoarGeoValue | undefined): ReactNode =>
  yesNo(value) ?? (text(value) || null);

const timeOf = (iso: unknown): string | null => {
  const value = text(iso);
  return value === "" ? null : formatDateTime(value);
};

/** The case of TheHive the SOAR opened (not the internal Tier-2 case of the summary), or why there is none. */
export function SoarCase({ view }: { view: AlertView }) {
  const block = view.soar?.case;
  if (!block) return null;
  const number = block.case_number;
  const hasNumber = number === null || typeof number === "string" || typeof number === "number";
  const items = visibleItems([
    { label: S.alert.soar.dedupKey, value: text(block.dedup_key) },
    { label: S.alert.soar.thehiveAlertId, value: text(block.thehive_alert_id) },
  ]);
  if (!hasNumber && items.length === 0) return null;
  const numberText = text(number);
  return (
    <Block title={S.alert.soar.caseTitle}>
      {hasNumber && (
        <p className="text-sm font-medium break-words">
          {numberText === "" ? S.alert.soar.noCase : S.alert.soar.caseNumber(numberText)}
        </p>
      )}
      <KeyValueGrid items={items} columns={1} />
    </Block>
  );
}

/** The action the SOAR planned: `type → target (tier, mode)`. */
export function SoarAction({ view }: { view: AlertView }) {
  const block = view.soar?.action;
  if (!block) return null;
  const detail = [text(block.tier), text(block.mode)].filter((part) => part !== "").join(", ");
  const action = S.alert.soar.action(text(block.type), text(block.target), detail);
  if (action === "") return null;
  return (
    <Block title={S.alert.soar.actionTitle}>
      <p className="font-mono text-sm break-words">{action}</p>
    </Block>
  );
}

/** The scenario and the SIEM's own score and signal for it: for reading, not for deciding. */
export function SoarScenario({ view }: { view: AlertView }) {
  const scenario = view.soar?.scenario;
  const triage = view.soar?.triage;
  const items: KeyValueItem[] = visibleItems([
    {
      label: S.alert.soar.scenario,
      value: S.alert.soar.scenarioName(text(scenario?.id), text(scenario?.name)),
    },
    { label: S.alert.soar.score, value: num(triage?.score) },
    { label: S.alert.soar.signal, value: text(triage?.signal_text) },
    { label: S.alert.soar.signalCodes, value: list(triage?.signal_codes).join(", ") },
  ]);
  if (items.length === 0) return null;
  const hasTriage = num(triage?.score) !== null || text(triage?.signal_text) !== "";
  return (
    <Block title={S.alert.soar.scenarioTitle}>
      <KeyValueGrid items={items} columns={1} />
      {hasTriage && <p className="text-xs text-muted">{S.alert.soar.scoreHint}</p>}
    </Block>
  );
}

/** How often the rule fired in the last seven days, and whether this host is new to it. */
export function SoarHistory({ view }: { view: AlertView }) {
  const history = view.soar?.history;
  if (!history) return null;
  const items = visibleItems([
    { label: S.alert.soar.ruleTotal7d, value: num(history.rule_7d_total) },
    { label: S.alert.soar.ruleHost7d, value: num(history.rule_7d_host) },
    { label: S.alert.soar.ruleHosts7d, value: num(history.rule_7d_hosts) },
    { label: S.alert.soar.firstSeenHost, value: yesNo(history.first_seen_host) },
    { label: S.alert.soar.lastSeen, value: timeOf(history.last_seen) },
  ]);
  if (items.length === 0) return null;
  return (
    <Block title={S.alert.soar.historyTitle}>
      <KeyValueGrid items={items} />
    </Block>
  );
}

/** GEO01: where the source address is from, field by field, only the fields the SIEM sent. */
export function SoarGeo({ view }: { view: AlertView }) {
  const geo = view.soar?.geo;
  if (!geo) return null;
  const country = text(geo.country);
  const items = visibleItems([
    {
      label: S.alert.soar.country,
      value:
        country === ""
          ? null
          : geo.country_simulated === true
            ? S.alert.soar.countryWithMark(country)
            : country,
    },
    // With no country to carry the mark, the flag is a row of its own.
    {
      label: S.alert.soar.countrySimulated,
      value: country === "" ? yesNo(geo.country_simulated) : null,
    },
    { label: S.alert.soar.srcIpType, value: geoValue(geo.src_ip_type) },
    { label: S.alert.soar.firstSeenCountry30d, value: geoValue(geo.first_seen_country_30d) },
    { label: S.alert.soar.seenCount30d, value: geoValue(geo.seen_count_30d) },
    { label: S.alert.soar.priorFailures30m, value: geoValue(geo.prior_failures_30m) },
    { label: S.alert.soar.impossibleTravel, value: geoValue(geo.impossible_travel) },
    { label: S.alert.soar.offHours, value: geoValue(geo.off_hours) },
  ]);
  if (items.length === 0) return null;
  return (
    <Block title={S.alert.soar.geoTitle}>
      <KeyValueGrid items={items} />
    </Block>
  );
}

/** SC03: the port scan the SIEM saw, a bounded sample of its ports, and the firewall lines folded away. */
export function SoarScan({ view }: { view: AlertView }) {
  const scan = view.soar?.scan;
  if (!scan) return null;
  const ports = list(scan.ports_sampled);
  const shown = ports.slice(0, PORTS_SHOWN);
  const total = Math.max(num(scan.ports_total) ?? 0, ports.length);
  const more = total - shown.length;
  const lines = typeof scan.previous_output === "string" ? scan.previous_output : "";
  const items = visibleItems([
    { label: S.alert.soar.sampledPackets, value: num(scan.sampled_packets) },
    { label: S.alert.soar.distinctPorts, value: num(scan.distinct_dst_ports_sampled) },
    {
      label: S.alert.soar.portsSample,
      value:
        shown.length === 0 ? null : (
          <>
            <span className="font-mono text-xs break-all">{shown.join(", ")}</span>
            {more > 0 && <span className="text-muted">{` ${S.alert.soar.morePorts(more)}`}</span>}
          </>
        ),
    },
    { label: S.alert.soar.dstIps, value: list(scan.dst_ips).join(", ") },
    { label: S.alert.soar.scanActions, value: list(scan.actions).join(", ") },
  ]);
  if (items.length === 0 && lines === "") return null;
  const cut = scan.previous_output_truncated === true;
  const lineCount = num(scan.previous_output_lines);
  return (
    <Block title={S.alert.soar.scanTitle}>
      <KeyValueGrid items={items} />
      {lines !== "" && (
        <details className="rounded border border-border">
          <summary className="cursor-pointer px-3 py-2 text-sm focus-visible:outline-2 focus-visible:outline-text">
            {cut && lineCount !== null
              ? S.alert.soar.previousOutputLines(lineCount)
              : S.alert.soar.previousOutput}
          </summary>
          <div className="p-3">
            <LogBlock text={lines} truncated={cut} label={S.alert.soar.previousOutput} />
          </div>
        </details>
      )}
    </Block>
  );
}

/** What the SOAR's threat-intelligence lookups said about the addresses of the alert. */
export function SoarTi({ view }: { view: AlertView }) {
  const ti = view.soar?.ti;
  const entries = (Array.isArray(ti) ? ti : []).flatMap((entry) => {
    const line = S.alert.soar.ti(text(entry?.type), text(entry?.value), text(entry?.verdict));
    return line === "" ? [] : [line];
  });
  if (entries.length === 0) return null;
  return (
    <Block title={S.alert.soar.tiTitle}>
      <ul className="space-y-1 text-sm">
        {entries.map((line, i) => (
          <li key={`${i}:${line}`} className="font-mono text-xs break-all">
            {line}
          </li>
        ))}
      </ul>
    </Block>
  );
}
