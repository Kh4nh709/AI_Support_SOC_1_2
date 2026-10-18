// The four confirmation dialogs of the users page (P11-T12, the canvas's "NGƯỜI DÙNG & QUYỀN" cards): change a
// role, deactivate, reset a password, unlock. Each owns its write, so a page mounts it while it is open and
// unmounts it to close it (`ConfirmDialog`'s own rule). Each:
//   - sends its write through `api/admin.ts` and, on success, invalidates through `invalidateAfter` and tells the
//     page what to say (`onDone`); the dialog never closes by itself;
//   - shows what went wrong inside the dialog (`failureOf`). A refusal no retry can change (the last active
//     admin, a change to oneself, a stale actor, an account that is gone) keeps the title and the alert and only
//     the button "Đóng" (`hideConfirm`); anything else leaves the buttons usable so the admin can try again;
//   - holds nothing typed after it closes: it is unmounted.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import {
  ADMIN_LIMITS,
  adminErrorOf,
  resetPassword,
  unlockUser,
  updateUser,
  type UserRow,
} from "../../../api/admin";
import type { Role } from "../../../api/types";
import { formatClock } from "../../../format";
import { S } from "../../../strings";
import { ConfirmDialog } from "../ConfirmDialog";
import { adminKeys, invalidateAfter, type AdminMutation } from "../adminKeys";
import { failureOf, passwordProblem, passwordProblemText, type Failure } from "../usersModel";

const T = S.admin.usersPage;

type DialogProps = {
  user: UserRow;
  /** Closes the dialog with nothing done. */
  onClose: () => void;
  /** The write succeeded and the list is being read again: say so, and close. */
  onDone: (notice: string) => void;
};

/** One write of the dialog, its failure, and what a failure does to the list behind it. */
function useUserWrite<V>(
  write: (value: V) => Promise<unknown>,
  invalidates: AdminMutation,
  done: () => void,
) {
  const client = useQueryClient();
  const [failure, setFailure] = useState<Failure | null>(null);
  const mutation = useMutation({
    mutationFn: write,
    onMutate: () => setFailure(null),
    onSuccess: async () => {
      await invalidateAfter(client, invalidates);
      done();
    },
    onError: (error) => {
      const read = failureOf(adminErrorOf(error));
      setFailure(read);
      // The list on screen may not be the truth any more (the account is gone, the admin count changed).
      if (read.reload) void client.invalidateQueries({ queryKey: adminKeys.users });
    },
  });
  return { mutation, failure, clearFailure: () => setFailure(null) };
}

/** The props every dialog hands `ConfirmDialog` for a failure: the alert, and the refusal's single button. */
function failureProps(failure: Failure | null, hideAlert = false) {
  const refused = failure?.refusal === true;
  return {
    error: failure !== null && !hideAlert ? failure.text : undefined,
    hideConfirm: refused,
    cancelLabel: refused ? S.common.close : undefined,
    refused,
  };
}

// --- role ---------------------------------------------------------------------------------------------------------

export function RoleChangeDialog({ user, to, onClose, onDone }: DialogProps & { to: Role }) {
  const write = useUserWrite(
    (role: Role) => updateUser(user.user_id, { role }),
    "updateUser",
    () => onDone(T.done.role(user.username, user.role, to)),
  );
  const view = failureProps(write.failure);
  return (
    <ConfirmDialog
      title={T.dialog.role.title(user.username)}
      confirmLabel={T.dialog.role.confirm}
      busy={write.mutation.isPending}
      error={view.error}
      hideConfirm={view.hideConfirm}
      cancelLabel={view.cancelLabel}
      onConfirm={() => write.mutation.mutate(to)}
      onCancel={onClose}
    >
      {!view.refused && (
        <>
          <p className="font-mono text-sm text-text">{T.dialog.role.change(user.role, to)}</p>
          <p>{T.dialog.role.body(user.username)}</p>
        </>
      )}
    </ConfirmDialog>
  );
}

// --- deactivate ---------------------------------------------------------------------------------------------------

export function DeactivateDialog({ user, onClose, onDone }: DialogProps) {
  const write = useUserWrite(
    () => updateUser(user.user_id, { is_active: false }),
    "updateUser",
    () => onDone(T.done.deactivate(user.username)),
  );
  const view = failureProps(write.failure);
  return (
    <ConfirmDialog
      title={T.dialog.deactivate.title(user.username)}
      confirmLabel={T.dialog.deactivate.confirm}
      tone="danger"
      busy={write.mutation.isPending}
      error={view.error}
      hideConfirm={view.hideConfirm}
      cancelLabel={view.cancelLabel}
      onConfirm={() => write.mutation.mutate(undefined)}
      onCancel={onClose}
    >
      {!view.refused && <p>{T.dialog.deactivate.body(user.display_name ?? user.username)}</p>}
    </ConfirmDialog>
  );
}

// --- reset password -----------------------------------------------------------------------------------------------

const FIELD =
  "h-10 w-full rounded-md border border-[#2e3a48] bg-[#0f141b] px-3 text-sm text-text focus-visible:outline-2 focus-visible:outline-text aria-invalid:border-[#5a2e36]";
const FIELD_ERROR = "text-[12.5px] text-[#fda4af]";

export function ResetPasswordDialog({
  user,
  own,
  onClose,
  onDone,
}: DialogProps & {
  /** The account is the caller's own: the reset ends their sessions too. */ own: boolean;
}) {
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const write = useUserWrite(
    (value: string) => resetPassword(user.user_id, value),
    "resetPassword",
    () => onDone(T.done.reset(user.username)),
  );
  const passwordId = useId();
  const repeatId = useId();
  const passwordErrorId = useId();
  const repeatErrorId = useId();

  // What is said at the password field: the server's own answer about it, else the live check of the length.
  const serverField = write.failure?.field === "password" ? write.failure.text : null;
  const problem = passwordProblem(password);
  const live = password !== "" && problem !== null ? passwordProblemText(problem) : null;
  const passwordError = serverField ?? live;
  const mismatch = repeat !== "" && repeat !== password;
  const valid = problem === null && repeat === password;

  const view = failureProps(write.failure, write.failure?.field === "password");
  // Editing the password makes the server's answer about it stale; the repeat has no answer of its own.
  const editPassword = (value: string) => {
    setPassword(value);
    write.clearFailure();
  };
  const busy = write.mutation.isPending;
  return (
    <ConfirmDialog
      title={T.dialog.reset.title(user.username)}
      confirmLabel={T.dialog.reset.confirm}
      busy={write.mutation.isPending}
      error={view.error}
      hideConfirm={view.hideConfirm}
      cancelLabel={view.cancelLabel}
      confirmDisabled={!valid}
      onConfirm={() => write.mutation.mutate(password)}
      onCancel={onClose}
    >
      {!view.refused && (
        <>
          <p>{T.dialog.reset.sessions(user.username)}</p>
          {own && (
            <p className="rounded-md border border-[#5a3a14] bg-[#2a1f12] px-3 py-2 text-[#fcd9a8]">
              {T.dialog.reset.own}
            </p>
          )}
          <div className="flex flex-col gap-1.5">
            <label htmlFor={passwordId} className="text-[13px] text-[#aeb9c6]">
              {T.dialog.reset.password}
            </label>
            <input
              id={passwordId}
              type="password"
              autoComplete="new-password"
              autoFocus
              value={password}
              readOnly={busy}
              aria-invalid={passwordError !== null ? true : undefined}
              aria-describedby={passwordError !== null ? passwordErrorId : undefined}
              onChange={(event) => editPassword(event.target.value)}
              className={FIELD}
            />
            {passwordError !== null && (
              <p id={passwordErrorId} role="alert" className={FIELD_ERROR}>
                {passwordError}
              </p>
            )}
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor={repeatId} className="text-[13px] text-[#aeb9c6]">
              {T.dialog.reset.repeat}
            </label>
            <input
              id={repeatId}
              type="password"
              autoComplete="new-password"
              value={repeat}
              readOnly={busy}
              aria-invalid={mismatch ? true : undefined}
              aria-describedby={mismatch ? repeatErrorId : undefined}
              onChange={(event) => setRepeat(event.target.value)}
              className={FIELD}
            />
            {mismatch && (
              <p id={repeatErrorId} role="alert" className={FIELD_ERROR}>
                {T.password.mismatch}
              </p>
            )}
          </div>
          <p className="text-xs leading-normal text-muted">
            {T.dialog.reset.hint(ADMIN_LIMITS.passwordMin)}
          </p>
        </>
      )}
    </ConfirmDialog>
  );
}

// --- unlock -------------------------------------------------------------------------------------------------------

export function UnlockDialog({ user, onClose, onDone }: DialogProps) {
  const write = useUserWrite(
    () => unlockUser(user.user_id),
    "unlockUser",
    () => onDone(T.done.unlock(user.username)),
  );
  const view = failureProps(write.failure);
  return (
    <ConfirmDialog
      title={T.dialog.unlock.title(user.username)}
      confirmLabel={T.dialog.unlock.confirm}
      busy={write.mutation.isPending}
      error={view.error}
      hideConfirm={view.hideConfirm}
      cancelLabel={view.cancelLabel}
      onConfirm={() => write.mutation.mutate(undefined)}
      onCancel={onClose}
    >
      {!view.refused && (
        <p>{T.dialog.unlock.body(formatClock(user.locked_until), user.failed_logins)}</p>
      )}
    </ConfirmDialog>
  );
}
