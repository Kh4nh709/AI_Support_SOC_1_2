import { BrowserRouter } from "react-router";
import { AuthProvider } from "./auth/AuthProvider";
import { AppRoutes } from "./routes";

// The router, then the session (it navigates), then the routes: the header and the page of the role.
// P10-T09 adds the live socket and the query client around the routes.
export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
