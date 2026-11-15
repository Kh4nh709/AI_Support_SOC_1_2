// The technical figures of an AI run, in the words of the analysis panel's mock-up: Vietnamese grouping and decimal
// comma ("21.480", "9,8 giây", "$0,0013"). A figure the run does not carry, or one that is not a finite number, is
// "—". Pure; nothing here knows a tier.
import { S } from "../../strings";

const LOCALE = "vi-VN";

const finite = (value: number | null | undefined): value is number =>
  typeof value === "number" && Number.isFinite(value);

/** A count (tokens): "21.480". */
export function formatCount(value: number | null | undefined): string {
  return finite(value)
    ? value.toLocaleString(LOCALE, { maximumFractionDigits: 0 })
    : S.common.missing;
}

/** Milliseconds as seconds with at most one decimal: "9,8 giây". */
export function formatSeconds(milliseconds: number | null | undefined): string {
  return finite(milliseconds)
    ? S.analysis.tech.seconds(
        (milliseconds / 1000).toLocaleString(LOCALE, { maximumFractionDigits: 1 }),
      )
    : S.common.missing;
}

/** Dollars with four decimals: "$0,0013". */
export function formatCost(dollars: number | null | undefined): string {
  return finite(dollars)
    ? `$${dollars.toLocaleString(LOCALE, { minimumFractionDigits: 4, maximumFractionDigits: 4 })}`
    : S.common.missing;
}
