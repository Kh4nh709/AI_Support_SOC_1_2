// The switch that turns the new-ticket signal (a tone and a browser notification) on and off. It is the one place that asks
// the browser for permission to notify, once, on the click that turns the signal on. The choice is kept by `storage.ts`
// and read again when the page is opened; with the store blocked the switch still moves, for this visit. When the browser
// will not show notifications (denied, or no such API) it says the tone is all there is.
import { useState } from "react";
import { S } from "../../strings";
import { notificationState, turnSignalOff, turnSignalOn } from "./signal";
import { readSignalOn } from "./storage";

export function SignalSwitch() {
  const [on, setOn] = useState(readSignalOn);
  // Read again after the browser has answered the permission request.
  const [, answered] = useState(0);
  const state = notificationState();

  const change = (next: boolean) => {
    setOn(next);
    if (next) void turnSignalOn().then(() => answered((n) => n + 1));
    else turnSignalOff();
  };

  return (
    <div className="flex flex-col gap-1">
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          role="switch"
          checked={on}
          onChange={(event) => change(event.target.checked)}
          className="h-4 w-4"
        />
        <span>{S.soar.signal.label}</span>
      </label>
      <p className="text-xs text-muted">{S.soar.signal.hint}</p>
      {(state === "denied" || state === "absent") && (
        <p className="text-xs text-muted">{S.soar.signal.toneOnly}</p>
      )}
    </div>
  );
}
