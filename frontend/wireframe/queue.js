import { S } from "../src/strings";
import { analysis, olderAnalysis } from "../src/features/tier1/analysisFixtures";
import { SC03, GEO, MW03 } from "../src/features/tier1/soarFixtures";
import { alertId,caseId,empty,me,now,page,json,scenario } from "./data";

const rules = [
 ["Unusual AMSI library load","execution","win-fin-17","112437"],
 ["Multiple SSH authentication failures","ssh_brute_force","srv-pay-02","5760"],
 ["External port scan detected","recon","fw-edge-01","5712"],
 ["Service configuration changed","policy_violation","srv-app-03","5300"]
];
const bands = Object.keys(S.band);
export const alerts = Array.from({length:57},(_,i)=>{
 const [description,category,agent_name,rule_id]=rules[i%4];
 const severity=bands[i%4], count=i===0?2:1+(i*13)%46;
 const id=i===0?alertId:alertId.slice(0,-4)+(4096+i).toString(16);
 const time=new Date(Date.parse(now)-i*91000).toISOString();
 const verdict=i%4===3?"false_positive":"true_positive";
 return {alert_id:id,rule_id,description,category,agent_name,severity,risk_band:S.band[severity],
   status:i===56?"tier1_active":"queued_tier1",acknowledged_by:i===56?me.user_id:null,
   alert_user:i%4===0?"Administrator":"ops",srcip:"192.0.2."+(11+i),occurrence_count:count,
   first_seen_at:time,last_seen_at:time,alert_time:time,suggestion_visible:true,suggested_action:verdict,
   gate_forced:i===3,needs_retriage:i===0,triage_status:"ready",confidence:i%2?"high":"medium",
 };
});
export const escalations=[];
const updates=new Map();
export function alertData(row) {
 const win=row.category==="execution",model=win?analysis():olderAnalysis();
 return {...row, requested_alert_id:row.alert_id, origin_host:row.agent_name,rule_level:9,
   event_time:row.alert_time, dstip:"198.51.100.20",src_port:54012,dst_port:443,decoder:win?"sysmon":"syslog",
   rule_groups:[row.category],mitre_ids:[win?"T1059":"T1110"],raw_log:win?model.reasons[0].quote:row.description+" · "+row.agent_name,
   asset_context:{present:true,criticality:"high",owner:"SOC",role:"server"},identity_context:{privileged:win},
   ioc_context:{reputation:"clean"},lookup_status:{asset:"found",identity:"found",ioc:"found"},
   targeted_accounts:[row.alert_user],playbook:"1. Đối chiếu thời điểm và tài khoản trong log.\n2. Kiểm tra lịch bảo trì với chủ máy.",
   soar:win?MW03:{...SC03,...GEO}, correlated_now:2,correlation:{rows:[{rule_id:row.rule_id,category:row.category,status:row.status,cluster_count:1,alert_count:row.occurrence_count,first_seen:row.first_seen_at,last_seen:row.last_seen_at,src_ip_count:1}],samples:[{...alerts[1]}]},
   suggestion:{suggested_action:row.suggested_action,confidence:row.confidence,created_at:row.alert_time,reasons:model.reasons,correlated_at_analysis:1},
   analysis:model,...updates.get(row.alert_id)
 };
}
let conflictShown=false;
if(scenario==="reopen") alerts[0].status="auto_closed";
if(scenario==="growth"){ alerts[0].status="tier1_active"; alerts[0].acknowledged_by=me.user_id; }
export function queueApi(path,q,body){
 if(path==="/tier1/queue"){
   let rows=(empty?[]:alerts).filter(r=>q.get("status")==="mine"?r.status==="tier1_active"&&r.acknowledged_by===me.user_id:r.status==="queued_tier1");
   if(q.get("category")) rows=rows.filter(r=>r.category===q.get("category"));
   if(q.get("agent")) rows=rows.filter(r=>r.agent_name.toLowerCase().includes(q.get("agent").toLowerCase()));
   const counts=Object.fromEntries(bands.map(b=>[b,rows.filter(r=>r.severity===b).length]));
   if(q.get("band")) rows=rows.filter(r=>r.severity===q.get("band"));
   const key={agent:"agent_name",occurrences:"occurrence_count",time:"last_seen_at"}[q.get("sort")];
   rows.sort((a,b)=>key?(a[key]>b[key]?1:a[key]<b[key]?-1:0)*(q.get("dir")==="asc"?1:-1):bands.indexOf(a.severity)-bands.indexOf(b.severity)||b.last_seen_at.localeCompare(a.last_seen_at));
   return {...page(rows,q),counts_by_band:counts};
 }
 const match=path.match(/^\/tier1\/alerts\/([^/]+)(?:\/(\w+))?$/);
 if(!match)return;
 const row=alerts.find(r=>r.alert_id===match[1]);
 if(!row||empty)return json({},404);
 const action=match[2];if(!action)return alertData(row);
 if(me.role!=="tier1")return json({},403);
 if(action==="acknowledge"){row.status="tier1_active";row.acknowledged_by=me.user_id;row.acknowledged_by_name=me.username;}
 if(action==="decide"){
   if(scenario==="growth"&&!conflictShown){conflictShown=true;row.occurrence_count+=12;return json({kind:"cluster_grew",seen_occurrence_count:body.seen_occurrence_count,occurrence_count:row.occurrence_count,delta:12,tolerance:2},409);}
   row.status=body.decision==="benign"?"closed_benign":"closed_fp";row.close_reason=body.reason;
 }
 if(action==="escalate"){row.status="escalated_tier2";row.case_id=crypto.randomUUID();escalations.push({case_id:row.case_id,title:body.title,severity:body.severity,alert:row});}
 if(action==="reopen"){row.status="queued_tier1";row.acknowledged_by=null;row.acknowledged_by_name=null;}
 return {...row,closed_count:row.occurrence_count,head_count:1};
}
