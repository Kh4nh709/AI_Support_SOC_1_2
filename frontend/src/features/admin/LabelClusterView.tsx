// The cluster on the labelling screen (spec §4.6): exactly what `labels/next` sends, one field at a time.
//
// BLIND (DEC-019, DEC-101; plan Review Focus 5). The server filters the cluster to `VIEW_KEYS`
// (tier1/labels.py) through the labelling filter; this file is the second wall. It renders each allowed field
// by name and nothing else: no loop over the keys of the cluster, no dump of it, no spread of it, so a key the
// server should never send has no way onto the page (LabelsPage.test.tsx plants some, and reads this file).
// It links to nothing: an alert page or a case page would show what was decided. `alert_id` and the `alert_id`
// of a sample are allowed keys, and are not shown: `gold_cluster_id` names the cluster, and is the same text.
import type { Ref } from "react";
import { useId } from "react";
import type { CorrelationRow, CorrelationSample, LabelCluster } from "../../api/admin";
import { BAND_CODES, type BandCode } from "../../api/types";
import { Badge } from "../../components/Badge";
import { type Column, DataTable } from "../../components/DataTable";
import { LogBlock } from "../../components/LogBlock";
import { formatDateTime, formatTime } from "../../format";
import { S } from "../../strings";

const C = S.admin.labelsPage.cluster;
const K = S.admin.labelsPage.correlation;

const PANEL = "flex flex-col gap-3 rounded-[10px] border border-border bg-surface px-5 py-4";
const MONO = "font-mono";
const PRE =
  "m-0 rounded-lg border border-console-divider bg-console-code-surface px-3.5 py-3 font-mono text-xs leading-[1.55] break-words whitespace-pre-wrap text-console-body";

/** A field that came as null (or empty) is a dash, never the word "null". */
function orDash(value: string | number | null): string {
  return value === null || value === "" ? S.common.missing : String(value);
}

/** The risk-band colour of a severity that is one of the four codes; any other text is shown plain. */
function bandOf(severity: string | null): BandCode | undefined {
  return BAND_CODES.find((code) => code === severity);
}

/**
 * The line above the two columns: category, severity, rule and level, cluster id. It takes the focus when a
 * write brings the next cluster (the button that held it is gone), so it can be focused and is not in the tab order.
 */
export function ClusterHead({ cluster, ref }: { cluster: LabelCluster; ref?: Ref<HTMLElement> }) {
  return (
    <section
      ref={ref}
      tabIndex={-1}
      aria-label={C.label}
      className="flex flex-wrap items-center gap-2.5 rounded-[10px] border border-border bg-surface px-4 py-3 text-[13.5px] focus-visible:outline-2 focus-visible:outline-text"
    >
      <span className="font-bold">{orDash(cluster.category)}</span>
      <Badge band={bandOf(cluster.severity)}>{orDash(cluster.severity)}</Badge>
      <span className="text-console-secondary">
        {C.rule} <span className={`${MONO} text-text`}>{orDash(cluster.rule_id)}</span>{" "}
        <span>{C.level(orDash(cluster.rule_level))}</span>
      </span>
      <span className="text-console-secondary">
        {C.clusterId} <span className={`${MONO} text-text`}>{cluster.gold_cluster_id}</span>
      </span>
    </section>
  );
}

function AlertPanel({ cluster }: { cluster: LabelCluster }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className={PANEL}>
      <h2 id={id} className="text-[15px] font-semibold">
        {C.alertTitle}
      </h2>
      <dl className="grid grid-cols-[150px_minmax(0,1fr)] gap-x-4 gap-y-2 text-[13.5px]">
        <dt className="text-muted">{C.time}</dt>
        <dd>{formatDateTime(cluster.alert_time)}</dd>
        <dt className="text-muted">{C.agent}</dt>
        <dd className={`${MONO} break-words`}>{orDash(cluster.agent_name)}</dd>
        <dt className="text-muted">{C.user}</dt>
        <dd className={`${MONO} break-words`}>{orDash(cluster.alert_user)}</dd>
        <dt className="text-muted">{C.route}</dt>
        <dd className={`${MONO} break-words`}>
          {orDash(cluster.srcip)} → {orDash(cluster.dstip)}
        </dd>
        <dt className="text-muted">{C.description}</dt>
        <dd className="break-words">{orDash(cluster.description)}</dd>
      </dl>
      <div className="flex flex-col gap-1.5">
        <h3 className="text-[13px] font-semibold text-console-secondary">{C.rawLog}</h3>
        <LogBlock text={cluster.raw_log} />
        {cluster.raw_log_truncated_for_display && (
          <p className="text-xs text-muted">{C.rawLogCut}</p>
        )}
      </div>
      <p className="text-[13.5px]">
        {C.seen(
          cluster.occurrence_count,
          formatTime(cluster.first_seen),
          formatTime(cluster.last_seen),
        )}
      </p>
    </section>
  );
}

const NUMBER = "text-right tabular-nums";

const ROW_COLUMNS: Column<CorrelationRow>[] = [
  {
    id: "rule",
    header: K.colRule,
    cell: (row) => <span className={MONO}>{orDash(row.rule_id)}</span>,
  },
  { id: "category", header: K.colCategory, cell: (row) => orDash(row.category) },
  {
    id: "clusters",
    header: K.colClusters,
    cell: (row) => row.cluster_count,
    className: NUMBER,
  },
  { id: "alerts", header: K.colAlerts, cell: (row) => row.alert_count, className: NUMBER },
  {
    id: "first",
    header: K.colFirst,
    cell: (row) => <span className="text-console-secondary">{formatTime(row.first_seen)}</span>,
  },
  {
    id: "last",
    header: K.colLast,
    cell: (row) => <span className="text-console-secondary">{formatTime(row.last_seen)}</span>,
  },
];

/** A correlated head, collapsed: one line of its facts, and its raw log as text inside. */
function Sample({ sample }: { sample: CorrelationSample }) {
  const facts = K.sample(
    orDash(sample.rule_id),
    orDash(sample.category),
    orDash(sample.severity),
    sample.occurrence_count,
    formatTime(sample.alert_time),
  );
  const description =
    sample.description === null || sample.description === "" ? "" : ` — ${sample.description}`;
  return (
    <details className="border-t border-console-divider pt-2.5">
      <summary className="cursor-pointer text-[13px] text-console-body focus-visible:outline-2 focus-visible:outline-text">
        {facts}
        {description}
      </summary>
      <pre className={`${PRE} mt-2`}>{sample.raw_log ?? ""}</pre>
    </details>
  );
}

function Correlation({ cluster }: { cluster: LabelCluster }) {
  const id = useId();
  const { rows, samples } = cluster.correlation;
  return (
    <section aria-labelledby={id} className={PANEL}>
      <h2 id={id} className="text-[15px] font-semibold">
        {K.title}
      </h2>
      {rows.length === 0 ? (
        <p className="text-[13.5px] text-console-body">{K.empty}</p>
      ) : (
        <DataTable
          label={K.table}
          columns={ROW_COLUMNS}
          rows={rows}
          rowKey={(row) => `${row.rule_id}/${row.category}/${row.first_seen}/${row.last_seen}`}
        />
      )}
      {samples.length > 0 && (
        <div role="group" aria-label={K.samples} className="flex flex-col gap-2.5">
          {samples.map((sample, index) => (
            <Sample key={`${sample.alert_id}/${index}`} sample={sample} />
          ))}
        </div>
      )}
    </section>
  );
}

function Playbook({ cluster }: { cluster: LabelCluster }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className={PANEL}>
      <h2 id={id} className="text-[15px] font-semibold">
        {C.playbook}
      </h2>
      <pre className={PRE}>{cluster.playbook}</pre>
    </section>
  );
}

/** The left column: the alert, what correlates with it, the playbook. */
export function ClusterDetails({ cluster }: { cluster: LabelCluster }) {
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4">
      <AlertPanel cluster={cluster} />
      <Correlation cluster={cluster} />
      <Playbook cluster={cluster} />
    </div>
  );
}
