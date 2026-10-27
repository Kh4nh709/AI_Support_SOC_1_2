// Fixtures of `view.soar` for the tests of the alert page: the blob `tier1/soar_view.py` makes of the SOAR
// team's two samples (MW03, SC03) and of the Owner's GEO01 field list. Test-only; nothing in the app imports it.
import type { SoarBlob } from "../../api/tier1";

/** What `GET /api/tier1/alerts/{id}` carries as `soar` for the MW03 sample (tier1/soar_view.py). */
export const MW03: SoarBlob = {
  case: {
    case_number: 50,
    thehive_alert_id: "~921656",
    dedup_key: "MW03|Windows_Endpoint|Virus:DOS/EICAR_Test_File|20261016-03",
    case_id: "~42700976",
  },
  action: { type: "none", target: "Windows_Endpoint", tier: "approval", mode: "act_first" },
  scenario: { id: "MW03", name: "Microsoft Defender malware detection" },
  triage: {
    score: 60,
    signal_text:
      "Defender detected Virus:DOS/EICAR_Test_File (Severe, Virus) via Real-Time Protection; remediation succeeded",
    signal_codes: ["defender_detection", "defender_remediation_succeeded"],
  },
  history: { rule_7d_total: 0, rule_7d_host: 0, rule_7d_hosts: 0, first_seen_host: true },
};

export const PORTS = Array.from({ length: 50 }, (_, i) => String(1000 + i));
export const FILTERLOG = "filterlog[21588]: 1,6,,1000000103,em1,match,block,in,4,0x0,,42,57120";

/** The SC03 sample: a scan of 180 ports, the filterlog lines, and one clean TI entry. */
export const SC03: SoarBlob = {
  case: {
    case_number: 55,
    thehive_alert_id: "~42799280",
    dedup_key: "SC03|pfSense||79.79.78.202|20261017-04",
    case_id: "~82747640",
  },
  action: { type: "block_ip", target: "79.79.78.202", tier: "auto", mode: "act_first" },
  scenario: { id: "SC03", name: "External port scan (pfSense)" },
  triage: {
    score: 50,
    signal_text:
      "79.79.78.202 sent TCP SYN to 20 distinct ports on the WAN within 1 minute (blocked by pfSense)",
    signal_codes: ["external_port_scan"],
  },
  history: {
    rule_7d_total: 4,
    rule_7d_host: 4,
    rule_7d_hosts: 1,
    last_seen: "2026-10-16T18:13:31.570Z",
    first_seen_host: false,
  },
  scan: {
    sampled_packets: 300,
    distinct_dst_ports_sampled: 180,
    ports_sampled: PORTS,
    ports_total: 50,
    dst_ips: ["79.79.78.75"],
    actions: ["block"],
    previous_output: `${FILTERLOG}\nfilterlog[21588]: 1,6,,1000000103,em1,match,block,in,4,0x0,,49,19170`,
    previous_output_truncated: false,
  },
  ti: [{ type: "ip", value: "79.79.78.202", verdict: "clean" }],
};

/** GEO01 is in no sample: the Owner's field list. */
export const GEO: SoarBlob = {
  geo: {
    country: "VN",
    country_simulated: true,
    src_ip_type: "external",
    first_seen_country_30d: true,
    seen_count_30d: 3,
    prior_failures_30m: 12,
    impossible_travel: false,
    off_hours: true,
  },
};
