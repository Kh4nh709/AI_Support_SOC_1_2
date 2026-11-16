// The number of open SOAR tickets inside the header's "Phản hồi SOAR" link, and the watch for a new one. It is mounted by
// the header only while somebody is signed in, so nothing is asked of the API before a login. The count asks every 30 s
// (also from a background tab, see `countQueryOptions`); a count that cannot be fetched leaves the link without a badge
// and breaks nothing: the header says nothing of it. When `latest_created_at` moves forward (never on the first answer
// this mount sees) the tone and the notification go, if the switch on the page is on (`signal.ts`).
import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { S } from "../../strings";
import { movedForward, signalNewTicket } from "./signal";
import { countQueryOptions } from "./soarQueries";

export function SoarNavBadge() {
  const { data } = useQuery(countQueryOptions());
  // The newest ticket last seen; `undefined` until the first answer, which only sets it.
  const seen = useRef<string | null | undefined>(undefined);

  useEffect(() => {
    if (data === undefined) return;
    const before = seen.current;
    seen.current = data.latest_created_at;
    if (before !== undefined && movedForward(before, data.latest_created_at)) {
      signalNewTicket(data.count);
    }
  }, [data]);

  if (data === undefined || !(data.count > 0)) return null;
  // The number is for the eye; the words are for a screen reader, which would otherwise read a bare "3" after the name.
  return (
    <>
      {" "}
      <span
        aria-hidden="true"
        className="ml-1 inline-block min-w-5 rounded-full bg-critical px-1.5 text-center text-xs font-semibold text-critical-bg"
      >
        {S.soar.badge.text(data.count)}
      </span>
      <span className="sr-only">{S.soar.badge.sr(data.count)}</span>
    </>
  );
}
