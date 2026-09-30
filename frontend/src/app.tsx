import { S } from "./strings";

// The placeholder layout of the scaffold (P10-T07). P10-T08 replaces it with the router, the session
// and the header; the two columns below are where P10-T10 puts the alert and the AI ① column.
export function App() {
  return (
    <div className="min-h-screen">
      <header className="flex items-center gap-4 border-b border-border bg-surface px-6 py-3">
        <span className="text-lg font-semibold">{S.app.name}</span>
      </header>
      <main className="grid grid-cols-2 gap-6 p-6">
        <section
          aria-labelledby="alert-heading"
          className="rounded border border-border bg-surface p-4"
        >
          <h2 id="alert-heading" className="text-sm font-medium tracking-wide text-muted">
            {S.alert.infoHeading}
          </h2>
        </section>
        <section
          aria-labelledby="ai-heading"
          className="rounded border border-ai-border bg-ai-surface p-4"
        >
          <h2 id="ai-heading" className="text-sm font-medium tracking-wide text-ai-accent">
            {S.alert.aiHeading}
          </h2>
        </section>
      </main>
    </div>
  );
}
