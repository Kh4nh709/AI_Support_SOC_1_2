// The reference of an IOC (the page of the IOC on abuse.ch): the ONE place of the page that may make a link, and only when
// `abuseChHref` says so (https, one of the three abuse.ch hosts exactly, no user, no other port). The link's words are the page's own,
// it opens in a new tab with `rel="noopener noreferrer"`, and its address is the one that was parsed and judged. Any other reference is
// shown defanged, as text, with a line that says why it is no link. The reference is also printed as text beside the link, through
// `shown`, so what the analyst reads is what is there.
import { S } from "../../strings";
import { abuseChHref, defang } from "./defang";
import { shown } from "./display";

export function Reference({ reference }: { reference: string | null }) {
  if (reference === null || reference === "") return <>{S.common.missing}</>;
  const href = abuseChHref(reference);
  if (href !== null) {
    return (
      <span className="flex flex-col gap-0.5">
        <span>
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-text"
          >
            {S.ti.detail.reference.open}
          </a>{" "}
          <span className="text-xs text-muted">({S.ti.detail.reference.newTab})</span>
        </span>
        <span className="font-mono text-xs wrap-anywhere">{shown(reference)}</span>
      </span>
    );
  }
  return (
    <span className="flex flex-col gap-0.5">
      <span className="font-mono text-xs wrap-anywhere">{shown(defang(reference, "url"))}</span>
      <span className="text-xs text-muted">{S.ti.detail.reference.notLinked}</span>
    </span>
  );
}
