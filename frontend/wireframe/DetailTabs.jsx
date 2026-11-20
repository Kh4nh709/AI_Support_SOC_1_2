import React, { Children, cloneElement } from "react";
import { Tabs as ApplicationTabs } from "../src/features/analysis/Tabs";
import { Summary as AlertSummary } from "../src/features/tier1/AlertSections";
import * as soarSections from "../src/features/tier1/SoarSections";

const soarBlocks = new Set(Object.values(soarSections));

function evidencePanels(content) {
  const [heading, summary, ...sections] = Children.toArray(content.props.children);
  const isAlert = summary?.type === AlertSummary;
  const soar = sections.filter((child) => soarBlocks.has(child.type));

  return cloneElement(content, { className: "wf-evidence" },
    <section key="summary" className="wf-summary">
      <header>{isAlert && <h2>Dữ liệu cảnh báo</h2>}{heading}</header>
      {summary}
    </section>,
    sections.map((section) => {
      if (!soarBlocks.has(section.type)) return section;
      if (section !== soar[0]) return null;
      return <section key="soar" className="wf-soar-context">
        <h2>Ngữ cảnh SOAR</h2>
        {soar}
      </section>;
    }),
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
