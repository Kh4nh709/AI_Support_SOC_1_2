// Who the signed-in user is, by id. The session holds a token, a role and a name but no user id, and the
// panel must know whether an alert is HELD BY THIS USER (`acknowledged_by` is an id) before it offers a
// decision; `GET /api/auth/me` says. It is asked only where the answer matters, once per session (the key
// carries the token, and the cache is cleared when the session changes), and never guessed: until it
// answers the panel says it is finding out.
import { useQuery } from "@tanstack/react-query";
import { fetchMe } from "../../api/auth";
import type { Session } from "../../auth/session";

export function useMe(session: Session, enabled: boolean) {
  return useQuery({
    queryKey: ["me", session.token],
    queryFn: async () => {
      const me = await fetchMe();
      // The backend sends the id as a string (a uuid); the type of the client says number. Whatever it is,
      // it is compared as text.
      return { userId: String(me.user_id) };
    },
    enabled,
    staleTime: Infinity,
  });
}

/** Two user ids are the same user when they are the same text, whatever the case of a uuid. */
export function sameUser(
  a: string | number | null | undefined,
  b: string | null | undefined,
): boolean {
  if (a === null || a === undefined || b === null || b === undefined) return false;
  return String(a).toLowerCase() === b.toLowerCase();
}
