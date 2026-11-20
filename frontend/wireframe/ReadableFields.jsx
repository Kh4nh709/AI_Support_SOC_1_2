import React, { Children, cloneElement, isValidElement } from "react";
import { KeyValueGrid as Fields } from "../src/components/KeyValueGrid";
import { Reference as IocReference } from "../src/features/ti/Reference";
export { visibleItems } from "../src/components/KeyValueGrid";

// Soft breaks affect layout only. Selection, the original IOC and the copy action retain every character.
function readable(node) {
  if (typeof node === "string" && (node.includes("|") || /[a-f\d]{32,}/i.test(node))) {
    const parts = node.split(/([a-f\d]{32,}|[|/:])/i).flatMap((part) =>
      /^[a-f\d]{32,}$/i.test(part) ? part.match(/.{1,8}/g) : [part]
    ).filter(Boolean);
    return parts.map((part, i) => <React.Fragment key={i}>{i > 0 && <wbr />}{part}</React.Fragment>);
  }
  if (isValidElement(node) && typeof node.type === "string" && node.props.children != null) {
    return cloneElement(node, {}, Children.map(node.props.children, readable));
  }
  return node;
}
export function KeyValueGrid({ items, ...props }) {
  return <Fields {...props} items={items.map((item) => ({ ...item, value: readable(item.value) }))} />;
}
export function Reference(props) {
  return readable(IocReference(props));
}
