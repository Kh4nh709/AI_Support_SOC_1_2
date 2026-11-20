import React,{useState} from "react";
import {createRoot} from "react-dom/client";
import {QueryClient,QueryClientProvider} from "@tanstack/react-query";
import {HashRouter, useLocation,useNavigate} from "react-router";
import {AppRoutes} from "../src/routes";
import {AuthContext} from "../src/auth/AuthProvider";
import {ApiError} from "../src/api/client";
import {S} from "../src/strings";
import {screens,settings,roles,me,scenario,alertId} from "./data";
import {installTransport} from "./transport";
import "../src/styles.css";
import "./preview.css";
installTransport();
const requested=settings.get("man");
const entry=screens.find(s=>s[0]===requested);
if(!location.hash)history.replaceState(null,"",location.pathname+location.search+"#"+(entry?.[2]||(requested==="missing"?"/alerts/missing":requested==="forbidden"?"/admin":"/")));
const initialPath=location.hash.slice(1).split("?")[0];
const initialRole=settings.get("role")||(initialPath.startsWith("/admin")&&requested!=="forbidden"?"admin":initialPath.startsWith("/cases")?"tier2":"tier1");
const query=new QueryClient({defaultOptions:{queries:{retry:false,refetchOnWindowFocus:false}}});
const modes=[["du-lieu","Có dữ liệu"],["dang-tai","Đang tải"],["rong","Rỗng"],["loi","Lỗi"],["offline",S.live.off]];
function reload(patch,path){
 const url=new URL(location.href);
 Object.entries(patch).forEach(([k,v])=>url.searchParams.set(k,v));
 url.hash=path;location.assign(url);if(url.search===location.search)location.reload();
}
function Demo(){
 const {pathname}=useLocation(),navigate=useNavigate();
 const role=Object.hasOwn(roles,initialRole)?initialRole:"tier1";
 const [session,setSession]=useState(initialPath==="/login"?null:{role,username:roles[role],token:"preview",expiresAt:"2099-01-01T00:00:00Z"});
 Object.assign(me,{role,username:session?.username||roles[role]});
 const screen=screens.find(s=>pathname===s[2])||screens.find(s=>s[0]==="case"&&pathname.startsWith("/cases/")||s[0]==="alert"&&pathname.startsWith("/alerts/")||s[0]==="admin-lab-run"&&pathname.startsWith("/admin/lab/"));
 const [gray,setGray]=useState(settings.get("mau")==="xam"),[mobile,setMobile]=useState(settings.get("kho")==="mobile");
 const framed=settings.has("frame");
 document.documentElement.dataset.gray=gray?"1":"0";
 const show=(s)=>reload({man:s[0],role:s[3],tt:"du-lieu"},s[2]);
 const extras=screen?.[0]==="alert"?[["growth","Cụm tăng lúc đang đọc"],["reopen",S.decision.reopen]]:[];
 const auth={ready:true,session,signedOut:session===null,logout:async()=>{query.clear();setSession(null);navigate("/login");},login:async(username)=>{setSession({role,username,token:"preview"});navigate(role==="admin"?"/admin/overview":role==="tier2"?"/cases":"/queue");}};
 const iframeUrl=new URL(location.href);iframeUrl.searchParams.set("frame","1");iframeUrl.searchParams.set("mau",gray?"xam":"mau");
 return <><div className="wf-tools" hidden={framed}><strong>Wireframe</strong>
 <label>Màn hình<select value={screen?.[0]||"catalog"} onChange={e=>e.target.value==="catalog"?navigate("/"):show(screens.find(s=>s[0]===e.target.value))}><option value="catalog">Danh mục</option>{screens.map(s=><option key={s[0]} value={s[0]}>{s[1]}</option>)}</select></label>
 <label>Vai trò<select value={role} onChange={e=>reload({role:e.target.value},pathname)}>{Object.entries(S.role).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select></label>
 <label>Trạng thái<select value={scenario} onChange={e=>reload({tt:e.target.value},pathname)}>{[...modes,...extras].map(([k,v])=><option key={k} value={k}>{v}</option>)}</select></label>
 <button aria-pressed={gray} onClick={()=>setGray(!gray)}>Màu</button><button aria-pressed={mobile} onClick={()=>setMobile(!mobile)}>375 px</button></div>
 {mobile&&!framed?<iframe title="Bố cục 375 px" src={iframeUrl.href}/>:pathname==="/"?<main className="wf-catalog"><h1>Danh mục wireframe</h1><div>{screens.map(s=><button key={s[0]} onClick={()=>show(s)}><strong>{s[1]}</strong><code>{s[2]}</code><small>{S.role[s[3]]}</small></button>)}</div></main>:<AuthContext.Provider value={auth}><AppRoutes/></AuthContext.Provider>}</>;
}
createRoot(document.getElementById("root")).render(<HashRouter><QueryClientProvider client={query}><Demo/></QueryClientProvider></HashRouter>);
