// Who the signed-in user is, by id. The session holds a token, a role and a name but no user id, and the
// panel must know whether an alert is HELD BY THIS USER (`acknowledged_by` is an id) before it offers a
// decision; `GET /api/auth/me` says. It is asked only where the answer matters, once per session (the cache
// is cleared when the token changes, LiveProvider, so the key need not carry it), and never guessed: until
// it answers the panel says it is finding out.
import { useQuery } from "@tanstack/react-query";
import { fetchMe } from "../../api/auth";

export function useMe(enabled: boolean) {
  return useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      const me = await fetchMe();
      return { userId: me.user_id };
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
