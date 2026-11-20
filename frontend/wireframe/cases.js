import { S } from "../src/strings";
import { runV4, RUN_ID } from "../src/features/tier2/runFixtures";
import { alerts, alertData, escalations } from "./queue";
import { caseId,empty,me,now,json,scenario } from "./data";

function makeCase(id,title,status,row){
 const open=status==="investigating",archived=status==="archived";
 const headStatus={investigating:"escalated_tier2",concluded_fp:"closed_fp",concluded_policy_violation:"closed_benign",confirmed_incident:"closed_confirmed",archived:"archived"}[status];
 return {case_id:id,title,status,severity:row.severity,created_by:"minh.nguyen",created_at:"2026-11-19T02:10:00Z",
   last_analyzed_at:"2026-11-20T01:31:00Z",last_run:{created_at:"2026-11-20T01:31:00Z",has_result:true},
   ongoing:open,ongoing_last_seen:open?now:null,cluster_count:1,occurrence_count:row.occurrence_count,
   concluded_at:open?null:now,concluded_by_name:open||archived?null:"linh.tran",conclusion_reason:open?null:"Đã đối chiếu bằng chứng và lịch vận hành.",
   heads:[{...alertData(row),status:headStatus}],notes:[]};
}
const cases=Object.keys(S.caseStatus).map((status,i)=>makeCase(i?caseId.slice(0,-1)+(i+1):caseId,["Điều tra tiến trình nạp AMSI","Đăng nhập theo lịch bảo trì","Kiểm tra tuân thủ trên máy biên","Sự cố đã xác nhận","Hồ sơ lưu trữ"][i],status,alerts[i]));
const states=new Map();
export function caseApi(path,q,body){
 if(!path.startsWith("/tier2/cases"))return;
 if(me.role==="tier1")return json({},403);
 for(const entry of escalations){if(!cases.some(c=>c.case_id===entry.case_id))cases.unshift(makeCase(entry.case_id,entry.title,"investigating",entry.alert));}
 if(path==="/tier2/cases"){const start=Number(q.get("offset"));return empty?[]:cases.slice(start,start+Number(q.get("limit")||50));}
 const [, , ,id,action]=path.split("/");
 const item=cases.find(c=>c.case_id===id);
 if(!item||empty)return json({},404);
 if(!action)return item;
 if(action==="notes"){
  const note={note_id:item.notes.length+1,case_id:id,body:body.body,author_id:me.user_id,author_name:me.username,created_at:new Date().toISOString()};
  item.notes.push(note);return note;
 }
 if(action==="conclude"){
  Object.assign(item,{status:body.conclusion,concluded_by:me.user_id,concluded_by_name:me.username,concluded_at:new Date().toISOString(),conclusion_reason:body.reason,ongoing:false});
  item.heads.forEach(h=>h.status={concluded_fp:"closed_fp",concluded_policy_violation:"closed_benign",confirmed_incident:"closed_confirmed"}[body.conclusion]);return item;
 }
 if(action==="analyze"){
  if(scenario==="quota")return json({detail:"quota exhausted"},429);
  states.set(id,"running");setTimeout(()=>{states.set(id,"done");item.ongoing=false;item.last_analyzed_at=new Date().toISOString();item.last_run={created_at:item.last_analyzed_at,has_result:true};},1600);
  return {run_id:RUN_ID,job_id:41};
 }
 if(action==="investigation"){
  const state=states.get(id)||(["idle","running","stalled","failed"].includes(scenario)?scenario:scenario==="quota"?"idle":"done");
  const current={alert_count:item.heads.length,total_occurrences:item.occurrence_count,last_seen_at:now};
  return {state,run_id:state==="idle"?null:RUN_ID,minutes:state==="stalled"?12:null,case_open:item.status==="investigating",current,run:state==="done"?runV4({snapshot:current,changed:item.ongoing}):null};
 }
}
