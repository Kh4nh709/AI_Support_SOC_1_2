import { useEffect } from "react";

// Reuse the real column headings when a narrow table is presented as records.
// Tables can arrive after a request or change columns when a filter changes.
export function useTableHeadings() {
  useEffect(() => {
    function label(table) {
      const headings = table.tHead?.rows[0]?.cells;
      if (!headings) return;
      table.parentElement.classList.add("wf-table-container");
      for (const body of table.tBodies) {
        for (const row of body.rows) {
          for (const cell of row.cells) {
            const header = headings[cell.cellIndex];
            if (cell.colSpan === 1 && header) cell.dataset.wfHeading = header.textContent.trim();
          }
        }
      }
    }
    const root = document.getElementById("root");
    root.querySelectorAll("table").forEach(label);
    const observer = new MutationObserver((records) => {
      const tables = new Set();
      for (const record of records) {
        const owner = record.target.parentElement?.closest("table") || record.target.closest?.("table");
        if (owner) tables.add(owner);
        for (const node of record.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;
          if (node.matches("table")) tables.add(node);
          node.querySelectorAll("table").forEach((table) => tables.add(table));
        }
      }
      tables.forEach(label);
    });
    observer.observe(root, { childList: true, subtree: true, characterData: true });
    return () => observer.disconnect();
  }, []);
}
