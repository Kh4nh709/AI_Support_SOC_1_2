import { tiFixture as fixture } from "../src/features/ti/fixtures";
import { empty,json,me,now,page } from "./data";

const dayMs=86400000;
const families=["Rat","Loader","Dropper","Stealer","Miner","Bot","Agent","Spy","Proxy","Worm"];
const samples=Array.from({length:68},(_,i)=>{
 const base=[fixture.ioc,fixture.hash,fixture.url,fixture.domain][i%4]();
 const date=new Date(Date.parse(now)-Math.floor(i*30/68)*dayMs).toISOString();
 const value=["203.0.113."+(i+1)+":443",(10000+i).toString(16).padStart(64,"0"),"https://feed"+i+".example.net/sample","host"+i+".example.net"][i%4];
 return {...base,id:1200-i,value,malware:"Example."+families[i%10],first_seen:date,last_seen:date,imported_at:date,
  confidence:base.confidence===null?null:[60,75,90,100][Math.floor(i/3)%4],expires_at:"2026-12-20T02:42:00Z"};
});
function statistics(rows){
 const by_day=Array.from({length:30},(_,i)=>{
  const day=new Date(Date.parse(now)-(29-i)*dayMs).toISOString().slice(0,10);
  const counts={day,threatfox:0,malwarebazaar:0,urlhaus:0,total:0};
  rows.filter(r=>r.first_seen.startsWith(day)).forEach(r=>{counts[r.source]++;counts.total++;});return counts;
 });
 const counts=new Map();rows.forEach(r=>counts.set(r.malware,(counts.get(r.malware)||0)+1));
 return fixture.stats({today:now.slice(0,10),by_day,top_malware:Array.from(counts,([malware,count])=>({malware,count})).sort((a,b)=>b.count-a.count||a.malware.localeCompare(b.malware)).slice(0,10),high_confidence:rows.filter(r=>r.confidence>=75).length,matched_in_logs:0,imported_today:by_day[29].total,newest_malware:[...new Set(rows.map(r=>r.malware))].slice(0,3)});
}
function filtered(rows,q){
 const needle=(q.get("q")||"").toLowerCase();
 return rows.filter(r=>["source","malware","type"].every(k=>!q.get(k)||r[k]===q.get(k))&&(!q.get("min_confidence")||r.confidence>=Number(q.get("min_confidence")))&&(!q.get("from")||r.first_seen.slice(0,10)>=q.get("from").slice(0,10))&&(!q.get("to")||r.first_seen.slice(0,10)<=q.get("to").slice(0,10))&&[r.value,r.malware,r.threat,...r.tags].some(v=>String(v||"").toLowerCase().includes(needle)));
}
export function tiApi(path,q){
 if(!path.startsWith("/ti/"))return;
 const rows=empty?[]:samples;
 if(path==="/ti/status"){const log=fixture.log({file:"ioc_2026-11-20.csv",started_at:now,finished_at:now,rows_total:3,rows_new:3,rows_updated:0});return fixture.status({latest:empty?null:log,latest_success:empty?null:log,stale:empty});}
 if(path==="/ti/stats")return statistics(rows);
 const hits=filtered(rows,q);
 if(path==="/ti/iocs")return page(hits,q);
 if(path==="/ti/export"){
  if(me.role!=="admin")return json({},403);
  if(q.get("format")==="blocklist"){
   const hosts=hits.filter(r=>r.type==="domain"||r.type==="ip:port").map(r=>r.value.split(":")[0]);
   return new Response([...new Set(hosts)].join("\n")+(hosts.length?"\n":""),{headers:{"Content-Type":"text/plain;charset=utf-8"}});
  }
  const keys=Object.keys(samples[0]);
  const cell=v=>'"'+String(Array.isArray(v)?v.join(","):v??"").replaceAll('"','""')+'"';
  return new Response("\uFEFF"+[keys.join(","),...hits.map(r=>keys.map(k=>cell(r[k])).join(","))].join("\r\n")+"\r\n",{headers:{"Content-Type":"text/csv;charset=utf-8"}});
 }
}
