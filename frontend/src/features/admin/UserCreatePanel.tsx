// The "Tạo người dùng" panel of the users page (P11-T12, the canvas's AdminUsers and its "TẠO NGƯỜI DÙNG · LỖI
// KIỂM TRA" card): username, display name, one of three roles, a temporary password and its repeat.
//
// What it checks before it posts is what the server checks without the database (`checkNewUser`), shown at
// the field with `aria-invalid`; the server's own answers show at the field too: `409 username_taken` and the
// `422 {field, reason}` of a username, a display name, a role or a password. Anything else (a refused
// actor, a 5xx, a lost connection) is an alert in the form. The password is posted once, in the body: the
// form empties when the account is made, and nothing here shows a password or keeps one.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState, type FormEvent } from "react";
import { ADMIN_LIMITS, adminErrorOf, createUser } from "../../api/admin";
import { ROLES, type Role } from "../../api/types";
import { S } from "../../strings";
import { invalidateAfter } from "./adminKeys";
import {
  NEW_USER_FIELDS,
  checkNewUser,
  failureOf,
  isNewUserField,
  type NewUserErrors,
  type NewUserField,
  type NewUserValues,
} from "./usersModel";

const C = S.admin.usersPage.create;

const EMPTY: NewUserValues = {
  username: "",
  displayName: "",
  role: null,
  password: "",
  repeat: "",
};

const LABEL = "flex flex-col gap-1.5 text-[13px] text-[#aeb9c6]";
const INPUT =
  "h-10 w-full rounded-md border border-[#2e3a48] bg-[#0f141b] px-3 text-sm text-text focus-visible:outline-2 focus-visible:outline-text aria-invalid:border-[#5a2e36]";
const ERROR = "text-[12.5px] text-[#fda4af]";

export function UserCreatePanel({
  onCreated,
}: {
  /** The account was made (and the list is being read again): say so. */
  onCreated: (notice: string) => void;
}) {
  const client = useQueryClient();
  const [values, setValues] = useState<NewUserValues>(EMPTY);
  const [errors, setErrors] = useState<NewUserErrors>({});
  const [formError, setFormError] = useState<string | null>(null);
  const titleId = useId();
  const ids = {
    username: useId(),
    display_name: useId(),
    role: useId(),
    password: useId(),
    repeat: useId(),
  } satisfies Record<NewUserField, string>;
  const fields = useRef<Partial<Record<NewUserField, HTMLElement | null>>>({});

  // A press of "Tạo tài khoản" sends one write: TanStack Query tells React a mutation is pending only on a timer, so
  // two presses in one tick would both find `isPending` false. The latch is released when the write settles. (P11-T14's
  // shared `useSubmitLatch` is to replace it.)
  const latch = useRef(false);
  const mutation = useMutation({
    mutationFn: createUser,
    // The variables of this mutation are a password. TanStack keeps them for `gcTime` (5 minutes by default), and
    // this panel lives as long as the page: nothing of a create is worth keeping once it has settled.
    gcTime: 0,
    onMutate: () => setFormError(null),
    onSuccess: async (_answer, body) => {
      await invalidateAfter(client, "createUser");
      setValues(EMPTY);
      setErrors({});
      onCreated(S.admin.usersPage.done.create(body.username, body.role));
    },
    onError: (error) => {
      const failure = failureOf(adminErrorOf(error));
      if (failure.field !== null && isNewUserField(failure.field)) {
        setErrors({ [failure.field]: failure.text });
      } else {
        setFormError(failure.text);
      }
    },
    onSettled: () => {
      latch.current = false;
    },
  });
  const { reset } = mutation;

  /** Sets one field, and drops the error that was about it (and, for the password, about the repeat). */
  const edit = (patch: Partial<NewUserValues>, ...cleared: NewUserField[]) => {
    setValues((current) => ({ ...current, ...patch }));
    setErrors((current) => {
      const next = { ...current };
      for (const field of cleared) delete next[field];
      return next;
    });
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (latch.current) return;
    const found = checkNewUser(values);
    setErrors(found);
    setFormError(null);
    const first = NEW_USER_FIELDS.find((field) => found[field] !== undefined);
    if (first !== undefined) {
      fields.current[first]?.focus();
      return;
    }
    if (values.role === null) return; // checked above; narrows the type
    latch.current = true;
    // `reset` once it has settled, whether it worked or not: the mutation, and the password in its variables,
    // are then dropped from the cache (this panel stays mounted, so it would otherwise hold them).
    mutation.mutate(
      {
        username: values.username,
        display_name: values.displayName,
        role: values.role,
        password: values.password,
      },
      { onSettled: () => reset() },
    );
  };

  const invalid = (field: NewUserField) => (errors[field] !== undefined ? true : undefined);
  const describedBy = (field: NewUserField) =>
    errors[field] !== undefined ? `${ids[field]}-error` : undefined;
  const message = (field: NewUserField) =>
    errors[field] !== undefined && (
      <p id={`${ids[field]}-error`} role="alert" className={ERROR}>
        {errors[field]}
      </p>
    );

  return (
    <section
      aria-labelledby={titleId}
      className="w-full max-w-[380px] rounded-[10px] border border-[#3a4757] bg-surface px-[22px] py-5"
    >
      <form noValidate onSubmit={submit} className="flex flex-col gap-3.5">
        <h2 id={titleId} className="text-[17px] font-semibold">
          {C.title}
        </h2>

        <div className={LABEL}>
          <label htmlFor={ids.username}>{C.username}</label>
          <input
            id={ids.username}
            ref={(el) => {
              fields.current.username = el;
            }}
            type="text"
            autoComplete="off"
            spellCheck={false}
            placeholder={C.usernamePlaceholder}
            value={values.username}
            aria-invalid={invalid("username")}
            aria-describedby={describedBy("username")}
            onChange={(event) => edit({ username: event.target.value }, "username")}
            className={`${INPUT} font-mono`}
          />
          {message("username")}
        </div>

        <div className={LABEL}>
          <label htmlFor={ids.display_name}>{C.displayName}</label>
          <input
            id={ids.display_name}
            ref={(el) => {
              fields.current.display_name = el;
            }}
            type="text"
            autoComplete="off"
            value={values.displayName}
            aria-invalid={invalid("display_name")}
            aria-describedby={describedBy("display_name")}
            onChange={(event) => edit({ displayName: event.target.value }, "display_name")}
            className={INPUT}
          />
          {message("display_name")}
        </div>

        <fieldset
          role="radiogroup"
          aria-invalid={invalid("role")}
          aria-describedby={describedBy("role")}
          className="m-0 flex flex-col gap-2 border-0 p-0"
        >
          <legend className="mb-1.5 text-[13px] text-[#aeb9c6]">{C.role}</legend>
          {ROLES.map((role: Role, index) => (
            <label
              key={role}
              className="flex items-start gap-2.5 rounded-lg border border-[#2e3a48] px-3 py-2.5 text-[13.5px]"
            >
              <input
                type="radio"
                name={ids.role}
                value={role}
                checked={values.role === role}
                ref={(el) => {
                  if (index === 0) fields.current.role = el;
                }}
                onChange={() => edit({ role }, "role")}
                className="mt-1"
              />
              <span>
                <b className="font-semibold">{role}</b>
                <span className="block text-[12.5px] text-muted">{C.roleHelp[role]}</span>
              </span>
            </label>
          ))}
          {message("role")}
        </fieldset>

        <div className={LABEL}>
          <label htmlFor={ids.password}>{C.password}</label>
          <input
            id={ids.password}
            ref={(el) => {
              fields.current.password = el;
            }}
            type="password"
            autoComplete="new-password"
            value={values.password}
            aria-invalid={invalid("password")}
            aria-describedby={describedBy("password")}
            onChange={(event) => edit({ password: event.target.value }, "password", "repeat")}
            className={INPUT}
          />
          {message("password")}
        </div>

        <div className={LABEL}>
          <label htmlFor={ids.repeat}>{C.repeat}</label>
          <input
            id={ids.repeat}
            ref={(el) => {
              fields.current.repeat = el;
            }}
            type="password"
            autoComplete="new-password"
            value={values.repeat}
            aria-invalid={invalid("repeat")}
            aria-describedby={describedBy("repeat")}
            onChange={(event) => edit({ repeat: event.target.value }, "repeat")}
            className={INPUT}
          />
          {message("repeat")}
        </div>

        <p className="text-xs leading-normal text-muted">{C.hint(ADMIN_LIMITS.passwordMin)}</p>

        {formError !== null && (
          <p
            role="alert"
            className="rounded-lg border border-[#5a2e36] bg-[#2a1016] px-3.5 py-3 text-[13.5px] leading-snug text-[#fda4af]"
          >
            {formError}
          </p>
        )}

        <button
          type="submit"
          disabled={mutation.isPending}
          aria-busy={mutation.isPending || undefined}
          className="h-11 rounded-lg bg-blue-600 text-[15px] font-semibold text-white hover:bg-blue-500 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text disabled:opacity-60"
        >
          {mutation.isPending ? S.admin.common.working : C.submit}
        </button>
      </form>
    </section>
  );
}
