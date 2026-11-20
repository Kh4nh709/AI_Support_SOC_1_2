import React, { Children, cloneElement } from "react";
import { Tabs as ApplicationTabs } from "../src/features/analysis/Tabs";
import {
  Correlation,
  Enrichment,
  EventDetails,
  RawLog,
  Summary as AlertSummary,
} from "../src/features/tier1/AlertSections";
import * as soarSections from "../src/features/tier1/SoarSections";

const soarBlocks = new Set(Object.values(soarSections));
const alertDataBlocks = new Set([EventDetails, RawLog, Enrichment]);

function evidencePanels(content) {
  const [heading, summary, ...sections] = Children.toArray(content.props.children);
  if (summary?.type !== AlertSummary) {
    return cloneElement(content, { className: "wf-evidence" },
      <section key="summary" className="wf-summary">
        <header>{heading}</header>
        {summary}
      </section>,
      sections,
    );
  }

  const soar = sections.filter((child) => soarBlocks.has(child.type));
  const alertData = sections.filter((child) => alertDataBlocks.has(child.type));
  const correlation = sections.filter((child) => child.type === Correlation);
  const other = sections.filter((child) =>
    !soarBlocks.has(child.type) && !alertDataBlocks.has(child.type) && child.type !== Correlation
  );
  const [, ...hint] = Children.toArray(heading.props.children);

  return cloneElement(content, { className: "wf-evidence wf-evidence-alert" },
    <div key="alert-data" className="wf-evidence-column">
      <section className="wf-summary">
        <header>
          <h2 id={content.props["aria-labelledby"]}>Dữ liệu cảnh báo</h2>
          {hint}
        </header>
        {summary}
      </section>
      {alertData}
    </div>,
    <div key="alert-context" className="wf-evidence-column">
      <section className="wf-soar-context">
        <h2>Ngữ cảnh SOAR</h2>
        {soar}
      </section>
      {other}
    </div>,
    correlation,
  );
}

// Keep navigation, keyboard handling, mounted forms and per-tab state in the app.
export function Tabs({ tabs, ...props }) {
  return <ApplicationTabs {...props} tabs={tabs.map((tab) =>
    tab.id === "evidence" && props.header
      ? { ...tab, content: evidencePanels(tab.content) }
      : tab
  )} />;
}
