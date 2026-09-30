// The live socket of the session, for the whole app (spec §3, P10-T05 server). It opens /api/ws for the
// token of the session and closes it with it, tells the components whether it is `live`, and turns each
// change into a throttled refetch of what is on screen. It does not fetch anything itself: the messages
// carry ids only, and what an alert now looks like is the API's answer, under the caller's own role.
import { useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { reportUnauthorized } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { createInvalidator } from "./invalidate";
import { connectLive, type LiveStatus } from "./socket";

// With no provider above (a page rendered alone) the socket is not there: offline, so the page polls.
const LiveContext = createContext<LiveStatus>("offline");

export function useLiveStatus(): LiveStatus {
  return useContext(LiveContext);
}

export function LiveProvider({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const queryClient = useQueryClient();
  const token = session?.token ?? null;
  // The status is kept with the token it was reported for, so a socket of an ended session never speaks
  // for the next one: until the new socket says `live`, the answer is offline.
  const [report, setReport] = useState<{ token: string; status: LiveStatus } | null>(null);

  useEffect(() => {
    if (token === null) return;
    const invalidator = createInvalidator(queryClient);
    const disconnect = connectLive({
      token: () => token,
      onChange: (change) => invalidator.push(change),
      onStatus: (status) => {
        setReport({ token, status });
        // Changes that came before `ready`, or while the socket was down, were not heard: read it all again.
        if (status === "live") invalidator.push("many");
      },
      onUnauthorized: reportUnauthorized,
    });
    return () => {
      disconnect();
      invalidator.cancel();
    };
  }, [token, queryClient]);

  // What one session fetched is not shown to the next, and a blind or a visible arm is decided per person:
  // the cache goes when the token does (sign-out, expiry, a new login), not when the same one is renewed.
  useEffect(
    () => () => {
      queryClient.clear();
    },
    [token, queryClient],
  );

  const status: LiveStatus = token !== null && report?.token === token ? report.status : "offline";
  return <LiveContext.Provider value={status}>{children}</LiveContext.Provider>;
}
