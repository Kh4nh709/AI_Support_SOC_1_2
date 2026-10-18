// `/admin/users` (P11-T12, spec §4.2): the accounts of the console, the actions each state allows, the four
// dialogs, the create panel and the read-only matrix of role to function. TanStack Query owns the one read
// (`adminKeys.users`); every write is made inside a dialog or the create panel, goes through `api/admin.ts`, and
// invalidates through `invalidateAfter`. There are no optimistic updates: a role select shows what the server
// has until the change is confirmed and the list is read again.
//
// The caller's own row is told by the session's username (a username is unique and cannot be renamed, and the
// login looks it up exactly). On it the role select and "Vô hiệu hoá" are disabled; the server still refuses
// the change with `409 self_change`, and the page shows that text too if it ever comes.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { adminErrorOf, listUsers, updateUser, type UserRow } from "../../api/admin";
import { ROLES, isRole, type Role } from "../../api/types";
import { useAuth } from "../../auth/AuthProvider";
import { DataTable, type Column } from "../../components/DataTable";
import { PageError } from "../../components/PageError";
import { Toast } from "../../components/Toast";
import { formatClock, formatTime } from "../../format";
import { S } from "../../strings";
import { RoleMatrix } from "./RoleMatrix";
import { RowMenu } from "./RowMenu";
import { UserCreatePanel } from "./UserCreatePanel";
import { adminKeys, invalidateAfter } from "./adminKeys";
import {
  DeactivateDialog,
  ResetPasswordDialog,
  RoleChangeDialog,
  UnlockDialog,
} from "./dialogs/UserDialogs";
import { accountState, failureOf, matchesSearch, type AccountState } from "./usersModel";

const T = S.admin.usersPage;

/** How often the page re-reads the clock, so a lock that has run out stops showing as a lock. */
const CLOCK_TICK_MS = 30_000;

/** The clock of the page, in milliseconds. It is state, not a read in render: render stays pure. */
function useNow(): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), CLOCK_TICK_MS);
    return () => clearInterval(timer);
  }, []);
  return now;
}

// Whole class names, written out: Tailwind finds a class by reading the source.
const STATE_CHIP: Record<AccountState, string> = {
  active: "bg-[#133528] text-[#9ff0c5]",
  locked: "bg-[#3a2a12] text-[#fcd9a8]",
  inactive: "bg-[#1c2530] text-[#8fa0b3]",
};

const ACTION =
  "h-[34px] whitespace-nowrap rounded-md border border-[#2e3a48] px-3 text-[13px] text-[#c9d3df] hover:bg-ground focus-visible:outline-2 focus-visible:outline-text disabled:cursor-not-allowed disabled:opacity-50";

/** The dialog that is open, and what it is about. A row's data is the row as it was when the dialog opened. */
type OpenDialog =
  | { kind: "role"; user: UserRow; to: Role }
  | { kind: "deactivate"; user: UserRow }
  | { kind: "reset"; user: UserRow }
  | { kind: "unlock"; user: UserRow };

function TableSkeleton() {
  return (
    <div
      role="status"
      aria-busy="true"
      className="space-y-2.5 rounded-[10px] border border-border bg-surface p-4"
    >
      <span className="sr-only">{S.common.loading}</span>
      {["a", "b", "c", "d", "e", "f"].map((key) => (
        <div key={key} className="h-10 animate-pulse rounded-md bg-[#1c2530]" />
      ))}
    </div>
  );
}

export function UsersPage() {
  const { session } = useAuth();
  const client = useQueryClient();
  const now = useNow();
  const query = useQuery({ queryKey: adminKeys.users, queryFn: listUsers });
  const [search, setSearch] = useState("");
  const [dialog, setDialog] = useState<OpenDialog | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  // Reactivating needs no dialog (the canvas draws none): it is undone by deactivating, and nobody is signed out.
  const reactivate = useMutation({
    mutationFn: (user: UserRow) => updateUser(user.user_id, { is_active: true }),
    onMutate: () => setProblem(null),
    onSuccess: async (_row, user) => {
      await invalidateAfter(client, "updateUser");
      setNotice(T.done.reactivate(user.username));
    },
    onError: (error) => {
      const failure = failureOf(adminErrorOf(error));
      setProblem(failure.text);
      if (failure.reload) void client.invalidateQueries({ queryKey: adminKeys.users });
    },
  });

  if (query.data === undefined && query.isError) {
    const error = adminErrorOf(query.error);
    // A role that is gone cannot read the list again: no retry for it.
    if (error.kind === "reason" && error.reason === "forbidden") {
      return <PageError title={S.admin.reason.forbidden} />;
    }
    return <PageError title={S.admin.common.loadError} onRetry={() => void query.refetch()} />;
  }

  const users = query.data?.users ?? null;
  const ownName = session?.username ?? null;
  const isOwn = (user: UserRow) => ownName !== null && user.username === ownName;
  const shown = users === null ? [] : users.filter((user) => matchesSearch(user, search));

  const done = (message: string) => {
    setDialog(null);
    setNotice(message);
  };

  const columns: readonly Column<UserRow>[] = [
    {
      id: "account",
      header: T.col.account,
      cell: (user) => (
        <>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[13px] font-semibold">{user.username}</span>
            {isOwn(user) && (
              <span className="rounded border border-border px-1.5 text-[11px] text-muted">
                {T.you}
              </span>
            )}
          </div>
          <div className="mt-0.5 text-[12.5px] text-muted">
            {user.display_name ?? S.common.missing}
          </div>
        </>
      ),
    },
    {
      id: "role",
      header: T.col.role,
      cell: (user) => (
        <select
          aria-label={T.roleSelect(user.username)}
          value={user.role}
          disabled={isOwn(user)}
          title={isOwn(user) ? S.admin.reason.self_change : undefined}
          onChange={(event) => {
            const to = event.target.value;
            if (isRole(to) && to !== user.role) setDialog({ kind: "role", user, to });
          }}
          className="h-9 w-[120px] rounded-md border border-[#2e3a48] bg-[#0f141b] px-2 text-[13px] text-text focus-visible:outline-2 focus-visible:outline-text disabled:cursor-not-allowed disabled:opacity-60"
        >
          {ROLES.map((role) => (
            <option key={role} value={role}>
              {role}
            </option>
          ))}
        </select>
      ),
    },
    {
      id: "status",
      header: T.col.status,
      cell: (user) => {
        const state = accountState(user, now);
        const label =
          state === "locked"
            ? T.status.locked(formatClock(user.locked_until))
            : state === "inactive"
              ? T.status.inactive
              : T.status.active;
        return (
          <span
            className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${STATE_CHIP[state]}`}
          >
            {label}
          </span>
        );
      },
    },
    {
      id: "lastLogin",
      header: T.col.lastLogin,
      cell: (user) => (
        <span className="text-[#aeb9c6]">
          {user.last_login_at === null ? T.neverLoggedIn : formatTime(user.last_login_at)}
        </span>
      ),
    },
    {
      id: "actions",
      header: T.col.actions,
      className: "text-right",
      cell: (user) => {
        const state = accountState(user, now);
        const own = isOwn(user);
        const name = (action: string) => T.rowAction(action, user.username);
        // An inactive account has one action. An active or a locked one has its main action and, behind the
        // row's "more" button, "Vô hiệu hoá" (disabled on the caller's own row).
        if (state === "inactive") {
          const reactivating =
            reactivate.isPending && reactivate.variables?.user_id === user.user_id;
          return (
            <div className="flex justify-end">
              <button
                type="button"
                aria-label={name(T.action.reactivate)}
                disabled={reactivating}
                aria-busy={reactivating || undefined}
                className={ACTION}
                onClick={() => reactivate.mutate(user)}
              >
                {T.action.reactivate}
              </button>
            </div>
          );
        }
        const [main, kind] =
          state === "locked"
            ? ([T.action.unlock, "unlock"] as const)
            : ([T.action.reset, "reset"] as const);
        return (
          <RowMenu
            label={T.moreActions(user.username)}
            disabled={own}
            title={S.admin.reason.self_change}
            leading={
              <button
                type="button"
                aria-label={name(main)}
                className={ACTION}
                onClick={() => setDialog({ kind, user })}
              >
                {main}
              </button>
            }
            items={[
              {
                id: "deactivate",
                label: T.action.deactivate,
                ariaLabel: name(T.action.deactivate),
                onSelect: () => setDialog({ kind: "deactivate", user }),
              },
            ]}
          />
        );
      },
    },
  ];

  const searching = search.trim() !== "";
  const empty = searching ? (
    <div className="space-y-2 py-4">
      <h2 className="text-[15px] font-semibold text-text">{T.noMatch.title(search.trim())}</h2>
      <p className="text-[13px] text-muted">{T.noMatch.hint}</p>
      <button type="button" className={ACTION} onClick={() => setSearch("")}>
        {T.noMatch.clear}
      </button>
    </div>
  ) : (
    T.empty
  );

  return (
    // The canvas is 1440 wide: the list and the matrix on the left, the create panel beside them. Under that
    // width the panel would squeeze the table, so it goes under the table instead (the markup order).
    <div className="grid grid-cols-1 items-start gap-x-6 gap-y-4 min-[1440px]:grid-cols-[minmax(0,1fr)_380px]">
      <div className="min-w-0 space-y-4 min-[1440px]:col-start-1 min-[1440px]:row-start-1">
        <div className="flex items-end gap-3">
          <div className="flex-1 space-y-1">
            <h1 className="text-[26px] font-semibold">{S.admin.title.users}</h1>
            <p className="min-h-5 text-sm text-[#aeb9c6]">
              {users !== null && T.count(users.length)}
            </p>
          </div>
          <label className="flex flex-col gap-1 text-xs text-muted">
            {T.search.label}
            <input
              type="search"
              placeholder={T.search.placeholder}
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              className="h-10 w-[220px] rounded-md border border-[#2e3a48] bg-[#0f141b] px-3 text-sm text-text focus-visible:outline-2 focus-visible:outline-text"
            />
          </label>
        </div>

        {problem !== null && (
          <div
            role="alert"
            className="flex items-start justify-between gap-3 rounded-lg border border-[#5a2e36] bg-[#2a1016] px-3.5 py-3 text-[13.5px] leading-snug text-[#fda4af]"
          >
            <span>{problem}</span>
            <button
              type="button"
              onClick={() => setProblem(null)}
              className="shrink-0 rounded border border-[#5a2e36] px-2 py-0.5 text-xs hover:bg-ground focus-visible:outline-2 focus-visible:outline-text"
            >
              {S.common.close}
            </button>
          </div>
        )}

        {users === null ? (
          <TableSkeleton />
        ) : (
          <DataTable
            label={T.tableLabel}
            columns={columns}
            rows={shown}
            rowKey={(user) => user.user_id}
            empty={empty}
            busy={query.isFetching}
          />
        )}
      </div>

      <div className="min-[1440px]:col-start-2 min-[1440px]:row-span-2 min-[1440px]:row-start-1">
        <UserCreatePanel onCreated={setNotice} />
      </div>

      <div className="min-w-0 min-[1440px]:col-start-1 min-[1440px]:row-start-2">
        <RoleMatrix />
      </div>

      {notice !== null && (
        <div className="fixed right-4 bottom-4 z-40 w-96">
          <Toast onClose={() => setNotice(null)}>
            <p>{notice}</p>
          </Toast>
        </div>
      )}

      {dialog?.kind === "role" && (
        <RoleChangeDialog
          user={dialog.user}
          to={dialog.to}
          onClose={() => setDialog(null)}
          onDone={done}
        />
      )}
      {dialog?.kind === "deactivate" && (
        <DeactivateDialog user={dialog.user} onClose={() => setDialog(null)} onDone={done} />
      )}
      {dialog?.kind === "reset" && (
        <ResetPasswordDialog
          user={dialog.user}
          own={isOwn(dialog.user)}
          onClose={() => setDialog(null)}
          onDone={done}
        />
      )}
      {dialog?.kind === "unlock" && (
        <UnlockDialog user={dialog.user} onClose={() => setDialog(null)} onDone={done} />
      )}
    </div>
  );
}
