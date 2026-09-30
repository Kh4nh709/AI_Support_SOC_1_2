import { QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { BrowserRouter } from "react-router";
import { createQueryClient } from "./api/queryClient";
import { AuthProvider } from "./auth/AuthProvider";
import { LiveProvider } from "./live/LiveProvider";
import { AppRoutes } from "./routes";

// The router, then the session (it navigates), then the query cache, then the live socket of the session
// (it refetches into the cache), then the routes: the header and the page of the role.
export function App() {
  const [queryClient] = useState(createQueryClient);
  return (
    <BrowserRouter>
      <AuthProvider>
        <QueryClientProvider client={queryClient}>
          <LiveProvider>
            <AppRoutes />
          </LiveProvider>
        </QueryClientProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
