// A page that is fetched when its route opens (`React.lazy`, P11-T20 row 56): the waiting line while it comes, and, when
// the fetch fails (the network, or a deploy that replaced the file this tab knows the name of), a title with a reload
// in its place. Without the boundary a rejected import is an error that nothing catches, and React unmounts the whole app.
//
// Only a failed fetch is offered a reload: a reload fetches the new `index.html` and cures it. A bug in the page (a
// render that throws) is not cured by one, so it gets its own text and no button, and the sidebar stays.
import { Component, Suspense, type ReactNode } from "react";
import { S } from "../strings";
import { PageError } from "./PageError";

/** What the browsers and Vite say when a dynamic `import()` or a preload fails (Chrome, Firefox, Safari, Vite). */
const CHUNK_FAILURE =
  /dynamically imported module|Importing a module script failed|Unable to preload CSS|ChunkLoadError/i;

/** Whether `error` is a chunk that could not be fetched, by its message. Anything else thrown is the page's own. */
export function isChunkLoadFailure(error: unknown): boolean {
  return CHUNK_FAILURE.test(error instanceof Error ? error.message : String(error));
}

type Failure = { children: ReactNode; reload: () => void };
type FailureState = { failure: "chunk" | "render" | null };

/** Catches what the lazy page throws, whether the fetch rejected or its render did. */
class LoadFailure extends Component<Failure, FailureState> {
  state: FailureState = { failure: null };

  static getDerivedStateFromError(error: unknown): FailureState {
    return { failure: isChunkLoadFailure(error) ? "chunk" : "render" };
  }

  // The error alone: the component stack that React offers here names the props of the page's components.
  componentDidCatch(error: unknown): void {
    console.error(error);
  }

  render(): ReactNode {
    if (this.state.failure === "chunk") {
      return <PageError title={S.admin.common.loadError} onRetry={this.props.reload} />;
    }
    if (this.state.failure === "render") {
      return (
        <p role="alert" className="rounded border border-high bg-high-bg px-4 py-2 text-high">
          {S.admin.common.renderError}
        </p>
      );
    }
    return this.props.children;
  }
}

/**
 * Wraps the lazy pages of one route. A failure stays until the boundary is mounted again: the caller gives it a `key`
 * that changes with the route, so the next page does not inherit the failure of the last. `reload` is a test seam; a
 * reload is what fixes a tab whose file names are out of date, because it asks for the new `index.html`. It runs on a
 * click only: the boundary never reloads by itself, so a chunk that stays missing cannot make a loop.
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
