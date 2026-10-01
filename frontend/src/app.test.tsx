import { render, screen } from "@testing-library/react";
import axe from "axe-core";
import { App } from "./app";
import { S } from "./strings";

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

// The scan above runs on the first paint, which is the loading screen: the session is not restored yet. The
// login form is the first thing every analyst sees, so it is scanned once it is on the page.
it("shows a login form with a labelled field for each input and no axe violation", async () => {
  const { container } = render(<App />);
  const username = await screen.findByLabelText(S.login.username);
  expect(username).toHaveAttribute("type", "text");
  expect(screen.getByLabelText(S.login.password)).toHaveAttribute("type", "password");
  expect(screen.getByRole("button", { name: S.login.submit })).toBeInTheDocument();
  expect(screen.getByRole("heading", { level: 1, name: S.login.title })).toBeInTheDocument();
  const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  expect(result.violations.map((v) => v.id)).toEqual([]);
});
