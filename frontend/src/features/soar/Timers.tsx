// The timers of a row (spec section 7): "Tự gỡ lúc HH:mm" with a countdown while the auto-undo is ahead; "Chờ SOAR đóng
// phiếu" once it is past and the ticket is still open (the web never changes a status itself); and, for an isolation or a
// locked account, "Đang giữ · nhắc mỗi N phút", with the word "Đã đến hạn nhắc" once the reminder is due. The words carry
// it: the highlight on a due reminder is colour AND text.
import type { SoarReview } from "../../api/soar";
import { S } from "../../strings";
import { useNowMs } from "./Clock";
import { timersOf } from "./model";

export function RowTimers({ row }: { row: SoarReview }) {
  const now = useNowMs();
  const { expiry, hold } = timersOf(row, now);
  if (expiry === null && hold === null) return null;
  return (
    <div className="mt-1 flex flex-col gap-0.5 text-xs">
      {expiry?.kind === "ahead" && (
        <p className="text-muted">{S.soar.timer.autoUndo(expiry.clock, expiry.left)}</p>
      )}
      {expiry?.kind === "past" && <p className="text-muted">{S.soar.timer.waitingClose}</p>}
      {hold !== null && <p className="text-muted">{S.soar.timer.holding(hold.minutes)}</p>}
      {hold?.due === true && <p className="font-semibold text-high">{S.soar.timer.remindDue}</p>}
    </div>
  );
}
