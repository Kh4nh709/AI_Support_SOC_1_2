// The "Trực tiếp" / "Mất kết nối" mark of the header. The dot is only decoration: the word says it, so it
// does not rest on colour.
import { S } from "../strings";
import { useLiveStatus } from "./LiveProvider";

export function LiveIndicator() {
  const live = useLiveStatus() === "live";
  return (
    <span role="status" className="flex items-center gap-1.5 text-sm text-muted">
      <span
        aria-hidden="true"
        className={`inline-block h-2 w-2 rounded-full ${live ? "bg-low" : "bg-critical"}`}
      />
      {live ? S.live.on : S.live.off}
    </span>
  );
}
