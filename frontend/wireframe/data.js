import { S } from "../src/strings";
export const settings = new URLSearchParams(location.search);
export const scenario = settings.get("tt") || "du-lieu";
export const empty = scenario === "rong";
export const roles = { tier1: "minh.nguyen", tier2: "linh.tran", admin: "an.pham" };
export const me = { user_id: "76a6f752-76c9-43f3-998f-4708345500ac", username: roles.tier1, role: "tier1" };
export const alertId = "gl-673dcc4882ab47fbbac7540f9a9b1000";
export const caseId = "dea517ad-4891-4547-93d3-4dbfdb661731";
export const labId = "141568be-90ba-414c-b467-c15604bc9483";
export const now = "2026-11-20T02:42:00Z";
export const screens = [
 ["queue",S.queue.title,"/queue","tier1"],["alert",S.alert.infoHeading,"/alerts/"+alertId,"tier1"],
 ["cases",S.case.listTitle,"/cases","tier2"],["case","Chi tiết case","/cases/"+caseId,"tier2"],
 ["soar",S.nav.soar,"/soar","tier1"],["ti",S.nav.ti,"/threat-intel","tier1"],
 ...Object.entries({overview:"Tổng quan",users:"Người dùng",llm:"LLM",labels:"Gán nhãn",lab:"Lab","lab-run":"Lần chạy lab",knowledge:"Tri thức",audit:"Audit"}).map(([key,title])=>["admin-"+key,title,"/admin/"+(key==="lab-run"?"lab/"+labId:key),"admin"]),
 ["login",S.login.title,"/login","tier1"]
];
export function page(rows, query, size = 50) {
  const n = Math.max(1,Number(query.get("page")) || 1);
  const limit = Number(query.get("page_size")) || size;
  return { rows: rows.slice((n-1)*limit,n*limit), total: rows.length, page:n, page_size:limit };
}
export function json(value,status=200) { return Response.json(value,{status}); }
