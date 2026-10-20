// A page that is fetched when its route opens (`React.lazy`, P11-T20 row 56): the waiting line while it comes, and, when
// the fetch fails (the network, or a deploy that replaced the file this tab knows the name of), a title with a reload
// in its place. Without the boundary a rejected import is an error that nothing catches, and React unmounts the whole app.
import { Component, Suspense, type ReactNode } from "react";
import { S } from "../strings";
import { PageError } from "./PageError";

type Failure = { children: ReactNode; reload: () => void };

/** Catches what the lazy page throws, whether the fetch rejected or its first render did. */
class LoadFailure extends Component<Failure, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  render(): ReactNode {
    if (this.state.failed) {
      return <PageError title={S.admin.common.loadError} onRetry={this.props.reload} />;
    }
    return this.props.children;
  }
}

/**
 * Wraps the lazy pages of one route. A failure stays until the boundary is mounted again: the caller gives it a `key`
 * that changes with the route, so the next page does not inherit the failure of the last. `reload` is a test seam; a
 * reload is what fixes a tab whose file names are out of date, because it asks for the new `index.html`.
 */
export function LazyPage({
  children,
  reload = () => window.location.reload(),
}: {
  children: ReactNode;
  reload?: () => void;
}) {
  return (
    <LoadFailure reload={reload}>
      <Suspense fallback={<p role="status">{S.common.loading}</p>}>{children}</Suspense>
    </LoadFailure>
  );
}
