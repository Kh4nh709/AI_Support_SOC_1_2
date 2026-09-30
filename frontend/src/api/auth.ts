// The three auth routes, one typed function each.
import { api } from "./client";
import type { LoginResponse, MeResponse } from "./types";

/** `POST /api/auth/login`: 401 bad credentials, 423 locked (`body.locked_until`), 503 auth disabled. */
export function postLogin(username: string, password: string): Promise<LoginResponse> {
  return api<LoginResponse>("/auth/login", { method: "POST", json: { username, password } });
}

/** `GET /api/auth/me`: who the token belongs to, and when it ends. */
export function fetchMe(): Promise<MeResponse> {
  return api<MeResponse>("/auth/me");
}

/** `POST /api/auth/logout`: 204. It invalidates every token issued before it. */
export function postLogout(): Promise<null> {
  return api<null>("/auth/logout", { method: "POST" });
}
