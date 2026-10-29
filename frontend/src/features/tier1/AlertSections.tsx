// The left column of the alert page (spec §3.2): what Wazuh sent and what the console added to it. Every block
// shows only when the view carries its data, so a sparse view is a short page and not a page of dashes. All
// of it is text: a value from the server (a log line, a description, an account) is never markup.
import type { ReactNode } from "react";
import { Link } from "react-router";
import type { AlertView, CorrelationRow, CorrelationSample } from "../../api/tier1";
import type { Role } from "../../api/types";
import { canOpenCases } from "../../caseAccess";
import { BandBadge } from "../../components/Badge";
import { CategoryText } from "../../components/CategoryText";
import { DataTable, type Column } from "../../components/DataTable";
import { KeyValueGrid, visibleItems, type KeyValueItem } from "../../components/KeyValueGrid";
import { LogBlock } from "../../components/LogBlock";
import { formatDateTime, formatTime } from "../../format";
import { S, labelOf } from "../../strings";

const LINK = "underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-text";

const alertPath = (id: string) => `/alerts/${encodeURIComponent(id)}`;

/** A titled block of the column. It is not a landmark: the column is one. */
export function Block({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <h3 className="text-sm font-semibold">{title}</h3>
      {children}
    </section>
  );
}

const joined = (list: readonly string[] | null | undefined): string | null =>
  list && list.length > 0 ? list.join(", ") : null;

const timeOf = (iso: string | null | undefined, format: (iso: string) => string): string | null =>
  iso ? format(iso) : null;

/** The band, the category and the status, then the counters and the times. */
export function Summary({ view, role }: { view: AlertView; role: Role | null }) {
  // The band is the server's own label (`risk_band`); with no score the alert's severity says it in words.
  const band = view.risk_band ?? (view.severity ? labelOf(S.band, view.severity) : null);
  const caseId = view.case_id;
  const items: KeyValueItem[] = [
    { label: S.alert.summary.rule, value: view.rule_id },
    { label: S.alert.summary.level, value: view.rule_level },
    { label: S.alert.summary.agent, value: view.agent_name },
    { label: S.alert.summary.occurrences, value: view.occurrence_count },
    { label: S.alert.summary.firstSeen, value: timeOf(view.first_seen_at, formatTime) },
    { label: S.alert.summary.lastSeen, value: timeOf(view.last_seen_at, formatTime) },
    { label: S.alert.summary.acknowledgedBy, value: view.acknowledged_by_name },
    { label: S.alert.summary.acknowledgedAt, value: timeOf(view.acknowledged_at, formatTime) },
    { label: S.alert.summary.closedAt, value: timeOf(view.closed_at, formatTime) },
    { label: S.alert.summary.closeReason, value: view.close_reason },
    {
      label: S.alert.summary.case,
      // Only a reader who may open the case pages is sent to them: Tier 1 is told which case, in text.
      value:
        caseId === null || caseId === undefined || caseId === "" ? null : canOpenCases(role) ? (
          <Link to={`/cases/${encodeURIComponent(String(caseId))}`} className={LINK}>
            {`${S.decision.goToCase} #${caseId}`}
          </Link>
        ) : (
          S.decision.caseNumber(caseId)
        ),
    },
  ];
  return (
    <section
      aria-label={S.alert.summaryLabel}
      className="space-y-3 rounded border border-border bg-surface p-3"
    >
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <BandBadge label={band} />
        <CategoryText code={view.category} />
        <span className="text-muted">{labelOf(S.status, view.status)}</span>
      </div>
      <KeyValueGrid items={items} columns={3} />
    </section>
  );
}

/** The fields of the event that Wazuh carried; none of them, no block. */
export function EventDetails({ view }: { view: AlertView }) {
  const items = visibleItems([
    { label: S.alert.field.srcip, value: view.srcip },
    { label: S.alert.field.dstip, value: view.dstip },
    { label: S.alert.field.srcPort, value: view.src_port },
    { label: S.alert.field.dstPort, value: view.dst_port },
    { label: S.alert.field.user, value: view.alert_user },
    { label: S.alert.field.decoder, value: view.decoder },
    { label: S.alert.field.ruleGroups, value: joined(view.rule_groups) },
    { label: S.alert.field.mitre, value: joined(view.mitre_ids) },
    { label: S.alert.field.source, value: view.source },
    { label: S.alert.field.originHost, value: view.origin_host },
    { label: S.alert.field.alertTime, value: timeOf(view.alert_time, formatDateTime) },
    { label: S.alert.field.eventTime, value: timeOf(view.event_time, formatDateTime) },
  ]);
  if (items.length === 0) return null;
  return (
    <Block title={S.alert.eventDetails}>
      <KeyValueGrid items={items} />
    </Block>
  );
}

export function RawLog({ view }: { view: AlertView }) {
  if (typeof view.raw_log !== "string" || view.raw_log === "") return null;
  return (
    <Block title={S.alert.rawLog}>
      <LogBlock text={view.raw_log} truncated={view.raw_log_truncated === true} />
    </Block>
  );
}

export function Accounts({ view }: { view: AlertView }) {
  const accounts = view.targeted_accounts;
  if (!accounts || accounts.length === 0) return null;
  return (
    <Block title={S.alert.accounts}>
      <ul className="flex flex-wrap gap-2">
        {accounts.map((account, i) => (
          <li
            key={`${i}:${account}`}
            className="rounded border border-border px-2 py-0.5 font-mono text-xs break-all"
          >
            {account}
          </li>
        ))}
      </ul>
    </Block>
  );
}

const triState = (value: boolean | null | undefined): string =>
  value === true ? S.alert.yes : value === false ? S.alert.no : S.common.missing;

/** What the asset, identity and IOC lookups found. What a lookup has not is said as "not known". */
export function Enrichment({ view }: { view: AlertView }) {
  const { asset_context: asset, identity_context: identity, ioc_context: ioc } = view;
  const lookups = view.lookup_status ? Object.entries(view.lookup_status) : [];
  if (!asset && !identity && !ioc && lookups.length === 0) return null;
  return (
    <Block title={S.alert.enrichment}>
      <KeyValueGrid
        items={[
          { label: S.alert.assetCriticality, value: asset?.criticality },
          { label: S.alert.assetOwner, value: asset?.owner },
          { label: S.alert.assetRole, value: asset?.role },
          { label: S.alert.identityPrivileged, value: triState(identity?.privileged) },
          { label: S.alert.iocReputation, value: ioc?.reputation ?? S.common.missing },
          {
            label: S.alert.lookupStatus,
            value:
              lookups.length === 0
                ? null
                : lookups
                    .map(([name, state]) => `${name}: ${labelOf(S.alert.lookup, state)}`)
                    .join(", "),
          },
        ]}
      />
    </Block>
  );
}

const CLUSTER_COLUMNS: readonly Column<CorrelationRow>[] = [
  { id: "rule", header: S.alert.correlationColumns.rule, cell: (row) => row.rule_id },
  { id: "category", header: S.alert.correlationColumns.category, cell: (row) => row.category },
  {
    id: "status",
    header: S.alert.correlationColumns.status,
    cell: (row) => labelOf(S.status, row.status),
  },
  {
    id: "alerts",
    header: S.alert.correlationColumns.alerts,
    className: "text-right tabular-nums",
    cell: (row) => row.alert_count,
  },
  {
    id: "span",
    header: S.alert.correlationColumns.span,
    className: "whitespace-nowrap",
    cell: (row) => `${formatTime(row.first_seen)} → ${formatTime(row.last_seen)}`,
  },
  {
    id: "srcIps",
    header: S.alert.correlationColumns.srcIps,
    className: "text-right tabular-nums",
    cell: (row) => row.src_ip_count,
  },
];

function Sample({ sample }: { sample: CorrelationSample }) {
  const meta = [
    sample.severity ? labelOf(S.band, sample.severity) : null,
    sample.status ? labelOf(S.status, sample.status) : null,
    typeof sample.occurrence_count === "number" ? `×${sample.occurrence_count}` : null,
    timeOf(sample.alert_time, formatTime),
  ].filter((part) => part !== null);
  return (
    <li className="space-y-0.5">
      <Link to={alertPath(sample.alert_id)} className={LINK}>
        {sample.description || sample.category || sample.alert_id}
      </Link>
      {meta.length > 0 && <p className="text-xs text-muted">{meta.join(" · ")}</p>}
    </li>
  );
}

/** The clusters of the ±2 h window, and a few alerts of them to open. */
export function Correlation({ view }: { view: AlertView }) {
  const correlation = view.correlation;
  if (!correlation) return null;
  const rows = correlation.rows ?? [];
  const samples = correlation.samples ?? [];
  return (
    <Block title={S.alert.correlation}>
      {typeof view.correlated_now === "number" && (
        <p className="text-xs text-muted">{S.alert.correlationHint(view.correlated_now)}</p>
      )}
      {rows.length === 0 ? (
        <p className="text-sm text-muted">{S.alert.noCorrelation}</p>
      ) : (
        <DataTable
          label={S.alert.correlation}
          columns={CLUSTER_COLUMNS}
          rows={rows}
          rowKey={(row) =>
            `${row.rule_id}|${row.category ?? ""}|${row.status}|${row.first_seen ?? ""}`
          }
        />
      )}
      {samples.length > 0 && (
        <div className="space-y-1">
          <h4 className="text-xs text-muted">{S.alert.correlationSamples}</h4>
          <ul className="space-y-2 text-sm">
            {samples.map((sample) => (
              <Sample key={sample.alert_id} sample={sample} />
            ))}
          </ul>
        </div>
      )}
    </Block>
  );
}

/** The playbook of the category, as text, or the sentence that there is none. Absent from the view, no block. */
export function Playbook({ view }: { view: AlertView }) {
  if (view.playbook === undefined) return null;
  return (
    <Block title={S.alert.playbook}>
      {view.playbook ? (
        <p className="text-sm break-words whitespace-pre-wrap">{view.playbook}</p>
      ) : (
        <p className="text-sm text-muted">{S.alert.noPlaybook}</p>
      )}
    </Block>
  );
}
