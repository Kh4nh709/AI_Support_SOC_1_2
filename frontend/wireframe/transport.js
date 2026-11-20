import {empty,me,json,scenario} from "./data";
import {queueApi} from "./queue";
import {caseApi} from "./cases";
const handlers=[queueApi,caseApi];
// All requests from product components stay in this document's sample store.
export function installTransport(){
 window.fetch=async (input,init={})=>{
  const url=new URL(typeof input==="string"?input:input.url, "http://wireframe.local");
  const path=decodeURIComponent(url.pathname.replace(/^\/api/,""));
  if(path==="/auth/me")return json(me);
  if(path==="/soar/reviews/count")return json({count:empty?0:4,latest_received_at:null});
  if(scenario==="dang-tai")return new Promise((_,reject)=>init.signal?.addEventListener("abort",()=>reject(new DOMException("Aborted","AbortError")),{once:true}));
  if(scenario==="loi")return json({},503);
  const body=init.body?JSON.parse(init.body):{};
  for(const handler of handlers){const value=await handler(path,url.searchParams,body,init.method||"GET");if(value!==undefined)return value instanceof Response?value:json(value);}
  return json({detail:"Bản ghi mẫu không tồn tại"},404);
 };
}
