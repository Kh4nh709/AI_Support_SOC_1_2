// src/api/queryClient.test.ts — which failures a query tries again.
import { ApiError } from "./client";
import { createQueryClient, shouldRetry } from "./queryClient";

describe("shouldRetry", () => {
  it("does not try a refusal again: a 4xx says the same the second time", () => {
    for (const status of [400, 401, 403, 404, 409, 422, 429]) {
      expect(shouldRetry(0, new ApiError(status, null))).toBe(false);
    }
  });

  it("tries a network error and a 5xx again, twice at most", () => {
    for (const error of [new TypeError("Failed to fetch"), new ApiError(503, null)]) {
      expect(shouldRetry(0, error)).toBe(true);
      expect(shouldRetry(1, error)).toBe(true);
      expect(shouldRetry(2, error)).toBe(false);
    }
  });

  it("is what the app's client uses for its queries", () => {
    expect(createQueryClient().getDefaultOptions().queries?.retry).toBe(shouldRetry);
  });
});
