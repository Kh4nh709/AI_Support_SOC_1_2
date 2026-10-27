// The category of an alert in words: the Vietnamese label of `S.category`, and the code beside it in mono
// (the code is what the queue's category filter and the playbooks are named by). A category this UI has no
// label for is the code alone, once. Text nodes only.
import { S, labelOf } from "../strings";

export function CategoryText({ code }: { code: string | null | undefined }) {
  if (code === null || code === undefined || code === "") return null;
  const label = labelOf(S.category, code);
  if (label === code) return <span className="font-mono text-xs">{code}</span>;
  return (
    <span className="inline-flex flex-wrap items-baseline gap-x-2">
      <span>{label}</span>
      <span className="font-mono text-xs text-muted">{code}</span>
    </span>
  );
}
