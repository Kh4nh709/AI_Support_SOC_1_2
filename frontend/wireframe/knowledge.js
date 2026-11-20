import sample from "./admin-samples.json";
import { empty, me, now, json, alertId, caseId } from "./data";
const { drafts, entries, tags } = sample.knowledge;
if (empty) {
  drafts.length = 0;
  entries.length = 0;
}
drafts.forEach(({ draft, source }, i) => {
  const subject = draft.source_kind === "alert" ? alertId : caseId;
  draft.source_id = source.id = subject;
  if (source.alert) {
    source.alert.alert_id = subject;
    source.alert.description = "External port scan detected";
  }
  if (source.case) source.case.case_id = subject;
  if (!draft.draft) {
    draft.draft = {};
    draft.warnings = ["budget"];
  } else if (i === 1) draft.draft.title = "Điều tra đợt quét đã lên lịch";
});
export function knowledgeApi(path, q, body) {
  const [, , , kind, id, action] = path.split("/");
  if (kind === "tags") return tags;
  if (kind === "entries") {
    if (!id) return entries.filter((e) => e.status === q.get("status"));
    const entry = entries.find((e) => e.entry_id === id);
    if (!entry) return json({}, 404);
    if (action === "retire") {
      entry.status = "retired";
      return { entry_id: id, status: "retired" };
    }
    return entry;
  }
  if (!id)
    return drafts
      .filter((d) => d.draft.status === q.get("status"))
      .map(({ draft }) => ({
        ...draft,
        title: draft.draft.title || null,
        has_text: Object.keys(draft.draft).length > 0,
      }));
  const detail = drafts.find((d) => d.draft.draft_id === id);
  if (!detail) return json({}, 404);
  const d = detail.draft;
  if (!action) return detail;
  if (d.status !== "pending") return json({ detail: { reason: "not_pending" } }, 409);
  if (action === "redraft") {
    drafts.splice(drafts.indexOf(detail), 1);
    return { draft_id: id, queued: true };
  }
  d.reviewed_at = now;
  d.reviewed_by_name = me.username;
  if (action === "reject") {
    d.status = "rejected";
    d.review_note = body.reason;
    return { draft_id: id, status: d.status };
  }
  if (action === "approve") {
    const fields = { ...d.draft, ...body.edited },
      entry_id = crypto.randomUUID();
    d.status = "approved";
    d.draft = fields;
    const entry = {
      ...entries[0],
      ...fields,
      entry_id,
      version: 1,
      status: "active",
      approved_at: now,
      approved_by_name: me.username,
      file_path: "entries/" + fields.category + "/" + entry_id + ".md",
      content: "# " + fields.title + "\n\n" + fields.summary,
      source_alert_ids: d.source_kind === "alert" ? [d.source_id] : [],
      source_case_ids: d.source_kind === "case" ? [d.source_id] : [],
    };
    entries.unshift(entry);
    return { entry_id };
  }
}
