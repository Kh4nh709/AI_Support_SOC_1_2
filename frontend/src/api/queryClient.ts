// The one QueryClient of the app. Its defaults are the ones every page wants; a test builds its own.
import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "./client";

/** A retry is for a network error or a 5xx: a refusal (4xx) says the same again. At most twice. */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (error instanceof ApiError && error.status < 500) return false;
  return failureCount < 2;
}

export function createQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: shouldRetry } } });
}
