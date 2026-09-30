// src/components/Badge.test.tsx — a row's band is coloured from the server's label through the one table of
// strings.ts; a label with no colour is shown as it came, in the neutral badge.
import { render, screen } from "@testing-library/react";
import { BAND_CODES } from "../api/types";
import { S } from "../strings";
import { BAND_SOLID, BandBadge, Badge } from "./Badge";

describe("BandBadge", () => {
  it.each(BAND_CODES)("colours the label of %s with that band's classes", (code) => {
    render(<BandBadge label={S.band[code]} />);
    const badge = screen.getByText(S.band[code]);
    for (const cls of BAND_SOLID[code].split(" ")) expect(badge).toHaveClass(cls);
  });

  it("gives the four bands four different colours", () => {
    expect(new Set(Object.values(BAND_SOLID)).size).toBe(4);
  });

  it("shows a label it has no colour for as it came, in the neutral badge", () => {
    render(<BandBadge label="Nghiêm trọng" />);
    const badge = screen.getByText("Nghiêm trọng");
    expect(badge).toHaveClass("text-muted");
    for (const code of BAND_CODES) {
      for (const cls of BAND_SOLID[code].split(" ")) expect(badge).not.toHaveClass(cls);
    }
  });

  it.each([null, undefined, ""])("shows a dash for %j", (label) => {
    render(<BandBadge label={label} />);
    expect(screen.getByText(S.common.missing)).toHaveClass("text-muted");
  });

  it("does not read a code as a label: the server's label is the input", () => {
    render(<BandBadge label="high" />);
    expect(screen.getByText("high")).toHaveClass("text-muted");
  });
});

describe("Badge", () => {
  it("renders its children as text", () => {
    render(<Badge>{"<b>x</b>"}</Badge>);
    expect(screen.getByText("<b>x</b>")).toBeInTheDocument();
  });
});
