import { render, screen } from "@testing-library/react";
import axe from "axe-core";
import { App } from "./app";

it("renders AI Support SOC", () => {
  render(<App />);
  expect(screen.getByText("AI Support SOC")).toBeInTheDocument();
});

it("has a banner and a main landmark and no axe violation", async () => {
  const { container } = render(<App />);
  expect(screen.getByRole("banner")).toBeInTheDocument();
  expect(screen.getByRole("main")).toBeInTheDocument();
  // jsdom computes no layout or colour, so the contrast rule cannot run here.
  const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  expect(result.violations.map((v) => v.id)).toEqual([]);
});
