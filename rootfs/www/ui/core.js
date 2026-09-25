// mini-router web UI core: DOM helper, API client, state, form widgets, page registry, layout,
// apply flow (validate → plan → apply → confirm/revert), login. Module pages live in ui/<module>.js
// and only use what is defined here. Contract: docs/MODULES.md.
"use strict";
// ---------- tiny DOM helper ----------
function h(tag, attrs, ...kids){
  const e = document.createElement(tag);
  for (const [k,v] of Object.entries(attrs||{})){
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "class") e.className = v;
    else if (k === "html") e.innerHTML = v;
    else if (k in e && typeof v !== "string") e[k] = v;
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat(Infinity)){
    if (k === null || k === undefined || k === false) continue;
    e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return e;
}
const $ = s => document.querySelector(s);
function toast(msg, ms){ const t=h("div",{class:"toast"},msg); document.body.append(t); setTimeout(()=>t.remove(), ms||2500); }
function fmtBytes(n){ n=+n||0; const u=["B","KB","MB","GB","TB"]; let i=0; while(n>=1024&&i<4){n/=1024;i++} return (i?n.toFixed(1):n)+" "+u[i]; }
function fmtRate(bps){ bps=+bps||0; if(bps<1e3) return bps.toFixed(0)+" bps"; if(bps<1e6) return (bps/1e3).toFixed(1)+" Kbps"; if(bps<1e9) return (bps/1e6).toFixed(1)+" Mbps"; return (bps/1e9).toFixed(2)+" Gbps"; }
function fmtDur(s){ s=Math.floor(+s||0); const d=Math.floor(s/86400),hh=Math.floor(s%86400/3600),m=Math.floor(s%3600/60); return (d?d+"天 ":"")+(d||hh?hh+"时 ":"")+m+"分"; }
const clone = o => JSON.parse(JSON.stringify(o));

// ---------- API ----------
async function api(action, body){
  const opt = {method: body===undefined?"GET":"POST", headers:{"X-MR":"1"}, credentials:"same-origin"};
  if (body!==undefined){ opt.headers["Content-Type"]="application/json"; opt.body=JSON.stringify(body); }
  const r = await fetch("/cgi-bin/api?a="+action, opt);
  pendingFrom(r);
  let j = {}; try { j = await r.json(); } catch(e) {}
  if (r.status===401 && action!=="login"){ S.auth=false; renderLogin(); throw new Error("未登录"); }
  if (!r.ok) { const e=new Error(j.error || (j.errors||[]).join("; ") || ("HTTP "+r.status)); e.data=j; throw e; }
  return j;
}

// ---------- change waiting for confirmation ----------
// Every API answer carries X-MR-Pending while a change is not accepted yet — made here, in another
// browser, by `mr apply` over SSH or by an agent. The banner on top of every page shows it with
// 保留 / 回滚; quiet pages ask every 10 s. No other change can be applied until it is settled.
const VIA = {"web UI":"网页", "mr apply":"命令行 mr apply", "restore":"恢复备份"};
function pendingFrom(r){
  let p = null;
  const v = r.headers.get("X-MR-Pending");
  if (v) try { p = JSON.parse(v); } catch(e) {}
  S.apiAt = Date.now();
  if (JSON.stringify(p) !== JSON.stringify(S.pend)){ S.pend = p; S.pendAt = Date.now(); drawPending(); }
}
function pendLeft(){ return Math.max(0, (S.pend.left||0) - Math.floor((Date.now()-S.pendAt)/1000)); }
function drawPending(){
  const b = $("#pbanner"); if (!b) return;
  const p = S.pend;
  b.classList.toggle("on", !!p);
  if (!p) return b.replaceChildren();
  const via = VIA[p.via] || p.via || "未知来源";
  if (p.state==="applying") return b.replaceChildren(h("span",{class:"t"}, h("b",{},"正在应用更改"), "（"+via+"）…"));
  if (p.state==="reverting") return b.replaceChildren(h("span",{class:"t"}, h("b",{},"正在回滚更改"), "（"+via+"）…"));
  const reload = async ()=>{ if (!dirty()){ await loadConfig(); show(S.page); } };
  b.replaceChildren(
    h("span",{class:"t"}, h("b",{},"有待确认的更改"), "（"+via+"）", p.state==="pending" ? [h("span",{id:"pleft"}, pendLeft()+" 秒"), "后自动回滚。"] : "。", h("span",{class:"mut"}," 确认前不能应用新的更改。")),
    h("button",{class:"btn sm d",onclick:async()=>{ if(!confirm("回滚这次更改（"+via+"）？")) return;
      try { await api("revert",{}); toast("正在回滚…",4000); setTimeout(()=>api("job").then(reload).catch(()=>{}), 5000); } catch(e){ toast(e.message,4000); } }},"回滚"),
    h("button",{class:"btn sm p",onclick:async()=>{
      try { await api("confirm",{}); toast("已保留新配置"); await api("job"); await reload(); } catch(e){ toast(e.message,4000); } }},"保留"));
}
setInterval(()=>{
  if (!S.auth) return;
  const e = $("#pleft"); if (e && S.pend) e.textContent = pendLeft()+" 秒";
  if (Date.now()-(S.apiAt||0) > 10000) api("job").catch(()=>{});
}, 1000);

// ---------- state ----------
const S = {
  auth:false, page:"overview", cfg:null, orig:"", secrets:{}, secretsSet:{},
  status:null, prevWan:{}, net:null, timer:null, tabs:{}, pend:null, pendAt:0, apiAt:0,
};
const dirty = () => S.cfg && (JSON.stringify(S.cfg)!==S.orig || Object.keys(S.secrets).length>0);
function touch(){ const p=$("#pending"); if(!p) return; p.classList.toggle("on", dirty()); }

async function loadConfig(){
  const j = await api("config");
  S.cfg = j.config; S.secretsSet = j.secrets_set||{}; S.secrets = {};
  const c = S.cfg;
  c.wan ||= []; c.policy_routes ||= []; c.static_routes ||= [];
  c.firewall ||= {}; c.firewall.forwards ||= []; c.firewall.open ||= []; c.firewall.ipv6_allow ||= []; c.firewall.rules ||= []; c.firewall.access ||= [];
  c.dhcp ||= {}; c.dhcp.hosts ||= []; c.dns ||= {}; c.dns.split ||= []; c.dns.addn_hosts ||= [];
  c.wifi ||= {}; c.wifi.radios ||= []; c.system ||= {}; c.system.ntp ||= []; c.system.sysctl ||= {};
  c.multicast ||= {}; c.lan ||= {}; c.lan.ports ||= []; c.networks ||= []; c.proxy ||= {}; c.multiwan ||= {}; c.schedules ||= []; c.services ||= {};
  for (const r of c.wifi.radios) r.ssids ||= [];
  S.orig = JSON.stringify(S.cfg);
  touch();
}

// ---------- form widgets (bound to obj[key]) ----------
function inText(obj, key, attrs){ return h("input",Object.assign({type:"text", value: obj[key]??"", oninput:e=>{obj[key]=e.target.value; touch();}}, attrs||{})); }
function inNum(obj, key, attrs){ return h("input",Object.assign({type:"number", value: obj[key]??0, oninput:e=>{obj[key]=e.target.value===""?0:Number(e.target.value); touch();}}, attrs||{})); }
function inBool(obj, key, onchange){ return h("label",{class:"sw"}, h("input",{type:"checkbox", checked:!!obj[key], onchange:e=>{obj[key]=e.target.checked; touch(); onchange&&onchange(e.target.checked);}}), h("span")); }
function inSel(obj, key, opts, onchange){
  const s = h("select",{onchange:e=>{obj[key]=e.target.value; touch(); onchange&&onchange(e.target.value);}},
    opts.map(o=>{ const [v,l]=Array.isArray(o)?o:[o,o]; return h("option",{value:v, selected: String(obj[key]??"")===String(v)}, l); }));
  if (obj[key]!==undefined && !opts.some(o=>String(Array.isArray(o)?o[0]:o)===String(obj[key]))) s.prepend(h("option",{value:obj[key],selected:true},obj[key]));
  return s;
}
function inList(obj, key, attrs){ // array of strings as comma/space separated text
  return h("input",Object.assign({type:"text", value:(obj[key]||[]).join(", "), oninput:e=>{obj[key]=e.target.value.split(/[\s,]+/).filter(Boolean); touch();}}, attrs||{}));
}
function inProto(obj, key){
  obj[key] ||= [];
  return h("span",{class:"row"}, ["tcp","udp"].map(p=>h("label",{}, h("input",{type:"checkbox", checked:obj[key].includes(p), onchange:e=>{
    const s=new Set(obj[key]); e.target.checked?s.add(p):s.delete(p); obj[key]=["tcp","udp"].filter(x=>s.has(x)); touch();}}), " "+p.toUpperCase())));
}
function inSecret(obj, key){ // obj[key] is the secret NAME; the value goes to S.secrets
  const name = obj[key];
  return h("input",{type:"password", autocomplete:"new-password",
    placeholder: name && S.secretsSet[name] ? "已设置（留空不变）" : "未设置",
    value: name && S.secrets[name] || "",
    oninput:e=>{ const n=obj[key]; if(!n) return; if(e.target.value) S.secrets[n]=e.target.value; else delete S.secrets[n]; touch(); }});
}
function field(label, input, hint){ return [h("label",{class:"l"},label), input, hint?h("div",{class:"hint"},hint):null]; }
function form(...rows){ return h("div",{class:"form"}, rows); }
function card(title, body, extra, flush){ return h("div",{class:"card"}, h("h2",{}, title, h("span",{class:"sp"}), extra||null), h("div",{class:"body"+(flush?" flush":"")}, body)); }

// editable table: cols = [{k, l, t:'text'|'num'|'bool'|'sel'|'proto'|'secret'|'list', o:[options], w, ph}]
function etable(arr, cols, blank, opts){
  opts ||= {};
  const tb = h("tbody");
  const draw = ()=>{
    tb.replaceChildren();
    if (!arr.length) tb.append(h("tr",{}, h("td",{colspan:cols.length+1, class:"mut"}, "（空）")));
    arr.forEach((row,i)=>{
      tb.append(h("tr",{}, cols.map(c=>{
        let w;
        const a = {placeholder:c.ph||""};
        switch(c.t){
          case "num": w=inNum(row,c.k,a); break;
          case "bool": w=inBool(row,c.k); break;
          case "sel": w=inSel(row,c.k,typeof c.o==="function"?c.o():c.o); break;
          case "proto": w=inProto(row,c.k); break;
          case "secret": w=inSecret(row,c.k); break;
          case "list": w=inList(row,c.k,a); break;
          case "ro": w=h("span",{class:"mono"}, row[c.k]??""); break;
          default: w=inText(row,c.k,a);
        }
        return h("td",{style:c.w?"width:"+c.w:null}, w);
      }), h("td",{style:"width:1%;white-space:nowrap"},
        opts.noMove?null:h("button",{class:"btn sm",title:"上移",disabled:i===0,onclick:()=>{[arr[i-1],arr[i]]=[arr[i],arr[i-1]];touch();draw();}},"↑"), " ",
        h("button",{class:"btn sm d",onclick:()=>{arr.splice(i,1);touch();draw();}},"删除"))));
    });
  };
  draw();
  const t = h("div",{class:"tw"}, h("table",{}, h("thead",{}, h("tr",{}, cols.map(c=>h("th",{},c.l)), h("th",{}))), tb));
  const add = h("button",{class:"btn sm p",onclick:()=>{arr.push(typeof blank==="function"?blank():clone(blank)); touch(); draw();}},"+ 添加");
  return {el:t, add, redraw:draw};
}
function tableCard(title, arr, cols, blank, note){
  const t = etable(arr, cols, blank);
  return card(title, [note?h("div",{class:"mut",style:"padding:10px 16px 0"},note):null, t.el], t.add, true);
}
function roTable(cols, rows){
  return h("div",{class:"tw"}, h("table",{}, h("thead",{}, h("tr",{}, cols.map(c=>h("th",{},c)))),
    h("tbody",{}, rows.length? rows.map(r=>h("tr",{}, r.map(x=>h("td",{},x)))) : h("tr",{}, h("td",{colspan:cols.length,class:"mut"},"（空）")))));
}

// ---------- page registry & layout ----------
// Modules register pages with registerPage(group, id, title, order, render). render() returns a Node
// (or a Promise of one); it may set S.timer = setInterval(...) for live refresh (cleared on navigation).
const NAV_GROUPS = [
  ["status","状态"], ["network","网络"], ["wireless","无线"], ["proxy","代理"], ["firewall","防火墙"],
  ["routing","路由"], ["services","服务"], ["system","系统"],
];
const PAGES = {};
const NAVREG = [];
function registerPage(group, id, title, order, render){
  if (PAGES[id]) throw new Error("duplicate page id "+id);
  if (!NAV_GROUPS.some(g=>g[0]===group)) throw new Error("unknown nav group "+group);
  PAGES[id] = render;
  NAVREG.push({group, id, title, order});
}
function pageTitle(id){ const p=NAVREG.find(x=>x.id===id); return p?p.title:""; }

// per-browser conveniences (collapsed nav groups, theme): storage may be unavailable, never required
function pref(k, v){ try { if (v===undefined) return localStorage.getItem("mr."+k); if (v===null) localStorage.removeItem("mr."+k); else localStorage.setItem("mr."+k, v); } catch(e){} return null; }
const THEMES = [["", "◐", "跟随系统"], ["light", "☀", "浅色"], ["dark", "☾", "深色"]];
function applyTheme(t){ const r=document.documentElement; if (!r) return; if (t) r.dataset.theme = t; else delete r.dataset.theme; }
applyTheme(pref("theme")||"");
function themeBtn(){
  const b = h("button",{class:"hbtn",type:"button"});
  const draw = ()=>{ const t=THEMES.find(x=>x[0]===(pref("theme")||""))||THEMES[0]; b.textContent=t[1]; b.title="主题："+t[2]; };
  b.onclick = ()=>{ const i=THEMES.findIndex(x=>x[0]===(pref("theme")||"")); const t=THEMES[(i+1)%THEMES.length]; pref("theme", t[0]||null); applyTheme(t[0]); draw(); toast("主题："+t[2]); };
  draw(); return b;
}
const logo = size=>h("img",{src:"logo.svg",alt:"",width:size,height:size});

// mobile drawer: the ☰ button opens it; the backdrop, ✕, Esc and every link close it
function setNav(open){
  $("#nav").classList.toggle("open", open);
  $("#scrim").classList.toggle("on", open);
  document.body.classList.toggle("navopen", open);
}
window.addEventListener("keydown", e=>{ if (e.key==="Escape" && $("#nav")?.classList.contains("open")) setNav(false); });
// nav groups collapse on tap; the set of collapsed groups is remembered
function shutGroups(){ return (pref("navshut")||"").split(",").filter(Boolean); }
function setGroup(g, shut){
  const list = shutGroups().filter(x=>x!==g); if (shut) list.push(g);
  pref("navshut", list.length ? list.join(",") : null);
  document.querySelectorAll(`nav [data-g="${g}"]`).forEach(e=>e.classList.toggle("shut", shut));
}

function renderShell(){
  const shut = shutGroups();
  const group = (g, label, links)=>[
    h("div",{class:"grp"+(shut.includes(g)?" shut":""), "data-g":g, role:"button", tabindex:0,
      onclick:()=>setGroup(g, !shutGroups().includes(g)),
      onkeydown:e=>{ if (e.key==="Enter"||e.key===" "){ e.preventDefault(); setGroup(g, !shutGroups().includes(g)); } }},
      h("span",{},label)),
    h("div",{class:"items"+(shut.includes(g)?" shut":""), "data-g":g}, links)];
  const nav = h("nav",{id:"nav"},
    h("div",{class:"brand"}, logo(30), h("div",{class:"n"},"Mini-Router", h("small",{id:"brandsub"}, "")),
      h("button",{class:"x",type:"button",title:"关闭菜单","aria-label":"关闭菜单",onclick:()=>setNav(false)},"×")),
    NAV_GROUPS.map(([g,label])=>{
      const items = NAVREG.filter(p=>p.group===g).sort((a,b)=>a.order-b.order);
      return items.length ? group(g, label, items.map(p=>h("a",{href:"#"+p.id, "data-p":p.id, onclick:()=>setNav(false)},p.title))) : null;
    }),
    group("account", "账户", h("a",{href:"#", onclick:async e=>{e.preventDefault(); await api("logout",{}).catch(()=>{}); location.reload();}},"退出登录")));
  const pend = h("div",{id:"pending"},
    h("span",{class:"t"}, h("b",{},"有未应用的更改。"), h("span",{class:"mut"}," 应用前会先校验并显示变更计划，应用后需在倒计时内确认，否则自动回滚。")),
    h("button",{class:"btn",onclick:async()=>{ await loadConfig(); show(S.page); toast("已放弃更改"); }},"放弃"),
    h("button",{class:"btn p",onclick:startApply},"保存并应用"));
  $("#root").replaceChildren(h("div",{id:"app"}, nav, h("div",{id:"scrim",onclick:()=>setNav(false)}),
    h("main",{}, h("div",{class:"top"}, h("header",{}, h("button",{id:"menu",type:"button","aria-label":"菜单",onclick:()=>setNav(!$("#nav").classList.contains("open"))},"☰"),
        h("h1",{id:"title"},""), h("span",{class:"meta",id:"hmeta"},""), themeBtn()), h("div",{id:"pbanner",role:"status"})),
      h("div",{class:"content",id:"page"}))), pend);
  touch(); drawPending();
}
window.addEventListener("hashchange", ()=>show(location.hash.slice(1)||"overview"));

function show(p){
  if (!PAGES[p]) p="overview";
  S.page=p;
  clearInterval(S.timer); S.timer=null;
  document.querySelectorAll("nav a[data-p]").forEach(a=>a.classList.toggle("act", a.dataset.p===p));
  const g = (NAVREG.find(x=>x.id===p)||{}).group;
  if (g && shutGroups().includes(g)) setGroup(g, false); // never hide the page you are on
  setNav(false);
  $("#title").textContent = pageTitle(p);
  const pg = $("#page"); pg.replaceChildren(h("div",{class:"mut"},"加载中…"));
  Promise.resolve().then(()=>PAGES[p]()).then(el=>{ if(S.page===p) pg.replaceChildren(el); })
    .catch(e=>pg.replaceChildren(h("div",{class:"err"},"加载失败："+e.message)));
}

// ---------- extra shared widgets ----------
// addCSS: modules add their own styles (prefix class names with the module name).
function addCSS(text){ document.head.append(h("style",{}, text)); }
// tabs([["id","标题", ()=>Node], ...]) → Node with a tab strip; remembers the active tab per page.
function tabs(list){
  const key = "tab:"+S.page; let cur = S.tabs[key] || list[0][0];
  const strip = h("div",{class:"tabs"}); const body = h("div");
  const draw = ()=>{
    strip.replaceChildren(...list.map(([id,l])=>h("a",{class:id===cur?"act":"", onclick:()=>{ cur=id; S.tabs[key]=id; draw(); }}, l)));
    const t = list.find(x=>x[0]===cur) || list[0];
    body.replaceChildren(h("div",{class:"mut"},"加载中…"));
    const id = t[0];
    Promise.resolve().then(()=>t[2]()).then(el=>{ if (cur===id) body.replaceChildren(el); })
      .catch(e=>{ if (cur===id) body.replaceChildren(h("div",{class:"err"},"加载失败："+e.message)); });
  };
  draw();
  return h("div",{}, strip, body);
}
// lineChart(series, opts): tiny SVG chart. series = [{label, color, points:[[t, v], ...]}];
// opts = {height, fmt: v=>string, max}. The plot stretches to the card's width at a fixed pixel height;
// the value labels are HTML beside it, so neither text nor strokes get distorted.
function lineChart(series, opts){
  opts ||= {}; const W=600, H=opts.height||160, T=6, B=4;
  const all = series.flatMap(s=>s.points);
  if (!all.length) return h("div",{class:"mut"},"（暂无数据）");
  const t0=Math.min(...all.map(p=>p[0])), t1=Math.max(...all.map(p=>p[0]))||t0+1;
  const vmax = opts.max || Math.max(1, ...all.map(p=>p[1]));
  const X=t=>W*(t-t0)/Math.max(1,t1-t0), Y=v=>T+(H-T-B)*(1-v/vmax);
  const svg = svgEl("svg",{viewBox:`0 0 ${W} ${H}`, preserveAspectRatio:"none", class:"lc-svg", style:`height:${H}px`});
  const axis = h("div",{class:"lc-axis", style:`height:${H}px`});
  for (let i=0;i<=4;i++){ const v=vmax*i/4, y=Y(v);
    svg.append(svgEl("line",{x1:0,x2:W,y1:y,y2:y,stroke:"var(--line)","stroke-width":1,"vector-effect":"non-scaling-stroke"}));
    axis.append(h("span",{style:`top:${y.toFixed(1)}px`}, (opts.fmt||String)(v))); }
  for (const s of series){ if(!s.points.length) continue;
    svg.append(svgEl("polyline",{points:s.points.map(p=>X(p[0]).toFixed(1)+","+Y(p[1]).toFixed(1)).join(" "),fill:"none",stroke:s.color||"var(--acc)",
      "stroke-width":1.6,"stroke-linejoin":"round","vector-effect":"non-scaling-stroke"})); }
  return h("div",{}, h("div",{class:"lc"}, axis, svg), h("div",{class:"row",style:"font-size:12px;margin-top:4px"}, series.map(s=>h("span",{},h("span",{class:"dot",style:"background:"+(s.color||"var(--acc)")}), s.label))));
}
const COLORS = ["#2f6fed","#1f9d55","#d64545","#c98a0b","#8e44ad","#16a2b8","#e67e22","#7f8c8d"];
const svgEl = (t,a)=>{ const e=document.createElementNS("http://www.w3.org/2000/svg",t); for(const k in a) e.setAttribute(k,a[k]); return e; };
// level(p, warn, bad): "" | "warn" | "bad" — colour class for a usage percentage
function level(p, warn, bad){ return p==null ? "" : p>=(bad||90) ? "bad" : p>=(warn||70) ? "warn" : ""; }
// gauge({label, pct, value, sub, center, lv, extra}): a card with a usage ring (pct 0-100, null = not known yet)
// and its numbers; center overrides the text in the ring (default "NN%"), lv the colour class, extra goes below.
function gauge(o){
  const r=30, c=2*Math.PI*r, p = o.pct==null ? 0 : Math.max(0, Math.min(100, o.pct));
  const svg = svgEl("svg",{viewBox:"0 0 76 76"});
  svg.append(svgEl("circle",{cx:38, cy:38, r, fill:"none", stroke:"var(--line)", "stroke-width":7}),
    svgEl("circle",{cx:38, cy:38, r, fill:"none", class:"gauge-fg "+(o.lv ?? level(o.pct)), "stroke-width":7, "stroke-linecap":"round",
      "stroke-dasharray":(c*p/100).toFixed(1)+" "+c.toFixed(1), transform:"rotate(-90 38 38)"}));
  return h("div",{class:"card gauge"}, h("div",{class:"gauge-r"}, svg, h("div",{class:"gauge-p"}, o.center ?? (o.pct==null ? "…" : Math.round(p)+"%"))),
    h("div",{class:"gauge-t"}, h("div",{class:"l"},o.label), h("div",{class:"v"},o.value), o.sub?h("div",{class:"s"},o.sub):null, o.extra||null));
}
// spark(values, color, max): a small area chart of recent values, no axes
function spark(vals, color, max){
  const W=120, H=26, col = color||"var(--acc)";
  const svg = svgEl("svg",{viewBox:`0 0 ${W} ${H}`, preserveAspectRatio:"none", class:"spark"});
  if (!vals || vals.length<2) return svg;
  const m = max || Math.max(1e-9, ...vals), X=i=>(i*W/(vals.length-1)).toFixed(1), Y=v=>(H-1-(H-3)*Math.min(1, Math.max(0,v)/m)).toFixed(1);
  const line = vals.map((v,i)=>(i?"L":"M")+X(i)+","+Y(v)).join("");
  svg.append(svgEl("path",{d:line+"L"+W+","+H+"L0,"+H+"Z", fill:col, "fill-opacity":.13, stroke:"none"}),
    svgEl("path",{d:line, fill:"none", stroke:col, "stroke-width":1.5, "vector-effect":"non-scaling-stroke"}));
  return svg;
}
// cpuBusy(a, b): busy % between two /proc/stat samples (user nice system idle iowait irq softirq steal)
function cpuBusy(a, b){
  if (!a || !b) return null;
  const d = b.map((v,i)=>v-(a[i]||0)), tot = d.reduce((x,y)=>x+y,0);
  return tot>0 ? Math.max(0, 100-(d[3]+d[4])*100/tot) : null;
}
// confirmBtn(label, question, fn): a red button that asks before running fn.
function confirmBtn(label, question, fn){ return h("button",{class:"btn sm d",onclick:async()=>{ if(!confirm(question)) return; try{ await fn(); }catch(e){ toast(e.message,4000); } }}, label); }
// Overview notices: modules add hints about the current state (captive portal, subnet conflict, time
// zone ...). registerNotice(fn): fn(status) → Node | [Node] | null on every overview refresh.
// notice(level, text, ...buttons): level warn | bad | info. dismissKey: a × that hides this notice in
// this browser until its key changes.
const NOTICES = [];
function registerNotice(fn){ NOTICES.push(fn); }
function notice(level, text, ...btns){ return h("div",{class:"notice "+level}, h("span",{class:"t"}, text), btns); }
function dismissed(key){ return (pref("dismiss")||"").split("\n").includes(key); }
function dismissBtn(key){ return h("button",{class:"btn sm",title:"在这个浏览器里不再提示",onclick:e=>{
  const l = (pref("dismiss")||"").split("\n").filter(Boolean).slice(-19); l.push(key); pref("dismiss", l.join("\n"));
  e.target.closest(".notice").remove(); }},"×"); }

// ---------- core pages ----------
// overview gauges keep a short history for their sparklines (40 points = 2 min at 3 s)
const OV = {cpu:null, h:{cpu:[], mem:[], ct:[]}};
const ovPush = (k, v)=>{ if (v==null) return; const a=OV.h[k]; a.push(v); if (a.length>40) a.shift(); };
registerPage("status", "overview", "总览", 10, async ()=>{
  const wrap = h("div");
  const draw = async ()=>{
    const [s, m] = await Promise.all([api("status"), api("mon.now").catch(()=>null)]); const now = Date.now()/1000;
    const busy = m ? cpuBusy(OV.cpu, m.cpu) : null; if (m) OV.cpu = m.cpu;
    const rates = {};
    for (const w of s.wan||[]){ const p=S.prevWan[w.name]; if(p&&now>p.t){ rates[w.name]={rx:(w.rx-p.rx)*8/(now-p.t), tx:(w.tx-p.tx)*8/(now-p.t)}; } S.prevWan[w.name]={rx:w.rx,tx:w.tx,t:now}; }
    S.status = s;
    $("#brandsub").textContent = s.host||"";
    $("#hmeta").textContent = (s.version||"")+" · "+(s.kernel||"");
    const memUsed = s.mem_total_kb - s.mem_avail_kb, memPct = memUsed*100/s.mem_total_kb, ctPct = s.conntrack*100/s.conntrack_max;
    const ovUsed = s.overlay_total_kb - s.overlay_free_kb, temp = s.temp_mc ? s.temp_mc/1000 : null;
    ovPush("cpu", busy); ovPush("mem", memPct); ovPush("ct", s.conntrack);
    const cores = m && m.cpus ? m.cpus.length+" 核 · " : "";
    const wanCards = (s.wan||[]).map(w=>card(h("span",{},h("span",{class:"dot "+(w.up?"ok":"bad")}),"WAN · "+w.name),
      h("dl",{class:"kv"}, h("dt",{},"状态"),h("dd",{},w.up?"已连接 · "+fmtDur(w.uptime):"未连接"),
        h("dt",{},"IPv4"),h("dd",{class:"mono"},w.ip||"-"), h("dt",{},"接口"),h("dd",{class:"mono"},w.dev),
        h("dt",{},"实时"),h("dd",{}, rates[w.name]?"↓ "+fmtRate(rates[w.name].rx)+"  ↑ "+fmtRate(rates[w.name].tx):"…"),
        h("dt",{},"累计"),h("dd",{},"↓ "+fmtBytes(w.rx)+"  ↑ "+fmtBytes(w.tx)))));
    const wifiCards = (s.wifi||[]).map(w=>card(h("span",{},h("span",{class:"dot "+(w.up?"ok":"bad")}),w.ssid||w.ifname),
      h("dl",{class:"kv"}, h("dt",{},"接口"),h("dd",{class:"mono"},w.ifname), h("dt",{},"信道"),h("dd",{},(w.channel||"-")+" · "+(w.htmode||"-")),
        h("dt",{},"终端"),h("dd",{},w.clients))));
    const ts = s.tailscale||{};
    const notes = NOTICES.flatMap(f=>{ try { return [f(s)].flat().filter(Boolean); } catch(e){ return []; } });
    wrap.replaceChildren(
      h("div",{class:notes.length ? "notices" : ""}, notes),
      h("div",{class:"grid gauges"},
        gauge({label:"CPU", pct:busy, value:busy==null ? "…" : busy.toFixed(0)+" %", sub:cores+"负载 "+s.load, extra:spark(OV.h.cpu, null, 100)}),
        gauge({label:"内存", pct:memPct, value:fmtBytes(memUsed*1024), sub:"共 "+fmtBytes(s.mem_total_kb*1024)+" · 可用 "+fmtBytes(s.mem_avail_kb*1024), extra:spark(OV.h.mem, COLORS[4], 100)}),
        gauge({label:"连接数", pct:ctPct, value:String(s.conntrack), sub:"上限 "+s.conntrack_max+" · 硬件加速 "+s.hnat_bind, extra:spark(OV.h.ct, COLORS[5])}),
        gauge({label:"温度", pct:temp, center:temp==null ? "-" : temp.toFixed(0)+"°", lv:level(temp, 75, 90), value:temp==null ? "-" : temp.toFixed(1)+" °C", sub:"运行 "+fmtDur(s.uptime)}),
        s.overlay_total_kb ? gauge({label:"配置存储", pct:ovUsed*100/s.overlay_total_kb, value:fmtBytes(ovUsed*1024), sub:"共 "+fmtBytes(s.overlay_total_kb*1024)+" · 剩余 "+fmtBytes(s.overlay_free_kb*1024)}) : null),
      h("div",{class:"grid",style:"margin-top:14px"}, wanCards, wifiCards,
        card("Tailscale", h("dl",{class:"kv"}, h("dt",{},"状态"),h("dd",{},ts.state||"-"), h("dt",{},"地址"),h("dd",{class:"mono"},ts.ip||"-"), h("dt",{},"在线节点"),h("dd",{},(ts.peers_online??"-")+" / "+(ts.peers_total??"-"))))),
      card("服务", h("div",{class:"row"}, (s.services||[]).map(x=>h("span",{class:"tag "+(x.running?"ok":"bad")}, x.name)))),
      card("最近变更", h("pre",{}, (s.changes||[]).slice().reverse().join("\n")||"（无）")));
  };
  await draw();
  const t = setInterval(()=>draw().catch(()=>{}), 3000);
  S.timer = t;
  setTimeout(()=>{ if (S.timer===t) draw().catch(()=>{}); }, 800); // a second CPU sample right away
  return wrap;
});

// history: every change (who, when, comment, result, what changed); roll back to before any of them
// through the normal apply (verify + confirm countdown), or compare that config with the live one.
const RESULT = {applying:["应用中",""], applied:["已应用","ok"], pending:["待确认","warn"], confirmed:["已保留","ok"]};
function resultTag(r){
  const m = RESULT[r] || [r.startsWith("rolled back") ? "已回滚"+(r.includes("at boot")?"（开机）":"") : r, "bad"];
  return h("span",{class:"tag "+m[1], title:r}, m[0]);
}
function changeList(lines){ return h("pre",{class:"chg"}, lines.length ? lines.join("\n") : "（配置内容没有变化）"); }
registerPage("system", "history", "变更历史", 30, async ()=>{
  const j = await api("history");
  const rows = (j.revisions||[]).map(r=>{
    const more = h("div",{style:"display:none"}, changeList(r.changes||[]));
    const n = (r.changes||[]).length;
    return [h("b",{},"#"+r.rev), new Date(r.time*1000).toLocaleString(),
      (VIA[r.via]||r.via)+(r.from?" · "+r.from:""), r.comment||"", resultTag(r.result),
      h("div",{}, h("a",{href:"#",onclick:e=>{ e.preventDefault(); more.style.display = more.style.display ? "" : "none"; }}, n+" 项"), more),
      h("span",{class:"row"},
        h("button",{class:"btn sm",onclick:async()=>{ const d = await api("history.diff",{rev:r.rev});
          const m = modal("#"+r.rev+" 之前的配置 → 现在", [h("p",{class:"mut"},"回滚到 #"+r.rev+" 之前会撤销这些："), changeList(d.changes||[])], [h("button",{class:"btn p",onclick:()=>m.remove()},"关闭")]); }},"对比现在"),
        h("button",{class:"btn sm d",onclick:async()=>{
          if (!confirm("把配置恢复到 #"+r.rev+" 之前？会像普通更改一样应用，并需要在倒计时内确认。")) return;
          await runJob(()=>api("rollback",{rev:r.rev})); }},"回滚到此前"))];
  });
  const older = (j.snapshots||[]).map(s=>[h("span",{class:"mono"},s),
    h("button",{class:"btn sm d",onclick:async()=>{ if(!confirm("把配置恢复到快照 "+s+"？")) return; await runJob(()=>api("rollback",{snapshot:s})); }},"回滚到此")]);
  return h("div",{},
    card("变更（每次应用都有记录；回滚本身也是一次新的更改）", rows.length ? roTable(["#","时间","来源","备注","结果","变更","操作"], rows) : h("div",{class:"mut"},"还没有记录。"), null, true),
    older.length ? card("更早的快照（没有记录）", roTable(["快照","操作"], older), null, true) : null);
});

// ---------- apply flow ----------
function modal(title, body, buttons){
  const m = h("div",{class:"modal"}, h("div",{class:"box"}, h("h3",{},title), h("div",{class:"b"}, body), h("div",{class:"f"}, buttons)));
  document.body.append(m); return m;
}
async function startApply(){
  if (S.pend) return toast("有待确认的更改：请先在页面顶部点“保留”或“回滚”，再应用新的更改。", 5000);
  const payload = {config:S.cfg, secrets:S.secrets};
  let v;
  try { v = await api("validate", payload); } catch(e){ return toast("校验请求失败："+e.message, 5000); }
  if (v.errors && v.errors.length){
    const m = modal("配置有误，未应用", h("ul",{class:"err"}, v.errors.map(x=>h("li",{},x))), [h("button",{class:"btn p",onclick:()=>m.remove()},"返回修改")]);
    return;
  }
  const note = h("input",{type:"text",maxlength:200,placeholder:"备注（可选，记入变更历史）"});
  const r = v.risk || {level:"medium", reasons:[], effects:[]};
  const RL = {low:["低风险","ok","不重启服务：应用并验证后自动保留。"], medium:["中风险","warn","会重启服务，但不影响你当前的连接：应用并验证后自动保留。"],
    high:["高风险","bad","影响你的连接或路由器的关键设置：应用后需要你手动点“保留”，否则 120 秒后自动回滚。"]}[r.level] || ["?","",""];
  const m = modal("确认应用", [
    v.changes_known ? [h("div",{style:"margin-bottom:6px"},"配置变更："), changeList(v.changes||[])] : null,
    h("div",{style:"margin:8px 0 6px"}, v.empty?"没有文件变化。":"将执行："), h("pre",{}, v.plan||"(无)"),
    (r.effects||[]).length ? h("ul",{class:"mut",style:"margin:6px 0"}, r.effects.map(e=>h("li",{},e))) : null,
    h("div",{style:"margin:8px 0"}, h("span",{class:"tag "+RL[1]}, RL[0]), " ", RL[2]),
    (r.reasons||[]).length ? h("ul",{class:"err",style:"margin:4px 0 8px"}, r.reasons.map(e=>h("li",{},e))) : null,
    note],
    [h("button",{class:"btn",onclick:()=>m.remove()},"取消"), h("button",{class:"btn p",onclick:()=>{ m.remove(); doApply(Object.assign({comment:note.value.trim()}, payload), r); }},"应用")]);
}
async function doApply(payload, risk){ return runJob(()=>api("apply", Object.assign({confirm:120}, payload)), risk && risk.level!=="high"); }
// runJob starts an apply job (apply, rollback) and follows it: output, then 保留 / 立即回滚. auto: a
// low / medium risk change is kept by the page itself once it is applied, verified and the page still
// reaches the router (the confirm window only has to catch changes that cut the administrator off).
async function runJob(start, auto){
  try { await start(); } catch(e){
    const msg = e.data&&e.data.pending ? "有待确认的更改（"+(VIA[e.data.pending.via]||e.data.pending.via)+"）：请先在页面顶部点“保留”或“回滚”。"
      : e.data&&e.data.errors ? e.data.errors.join("\n") : e.message;
    return modal("应用失败", h("pre",{}, msg), [h("button",{class:"btn p",onclick:ev=>ev.target.closest(".modal").remove()},"关闭")]);
  }
  const log = h("pre",{},"");
  const stateEl = h("div",{style:"margin-bottom:8px"},"正在应用…");
  const foot = h("div",{class:"row"});
  const m = modal("应用配置", [stateEl, log], [foot]);
  let seenOk = 0, fails = 0;
  const poll = async ()=>{
    let j;
    try { j = await api("job"); fails = 0; } catch(e){ fails++; stateEl.textContent = "暂时连不上路由器（"+fails+"）… 如果是改了 LAN 地址，请到新地址访问；超时未确认会自动回滚。"; return setTimeout(poll, 2000); }
    const job = j.job||{}; log.textContent = job.output||"";
    if (job.state==="running") return setTimeout(poll, 1200);
    if (job.state==="failed"){
      stateEl.replaceChildren(h("b",{class:"err"},"应用失败，已自动回滚。"));
      foot.replaceChildren(h("button",{class:"btn p",onclick:async()=>{ m.remove(); await loadConfig(); show(S.page);} },"关闭"));
      return;
    }
    if (!j.confirm_pending){
      stateEl.replaceChildren(h("b",{style:"color:var(--ok)"},"已应用并保留。"));
      foot.replaceChildren(h("button",{class:"btn p",onclick:async()=>{ m.remove(); await loadConfig(); show(S.page);} },"完成"));
      return;
    }
    if (auto && !seenOk){
      try { await api("confirm",{}); } catch(e){ auto = false; return setTimeout(poll, 500); }
      stateEl.replaceChildren(h("b",{style:"color:var(--ok)"},"已应用并自动保留"), h("span",{class:"mut"},"（不影响你的连接；要撤销请到“变更历史”回滚）。"));
      foot.replaceChildren(h("button",{class:"btn p",onclick:async()=>{ m.remove(); await loadConfig(); show(S.page);} },"完成"));
      return;
    }
    if (!seenOk){
      seenOk = Date.now();
      const left = h("span",{});
      const tick = setInterval(()=>{ const s=Math.max(0, (job.confirm||120) - Math.floor((Date.now()-seenOk)/1000)); left.textContent = s+" 秒后自动回滚"; if(!s) clearInterval(tick); }, 500);
      stateEl.replaceChildren(h("b",{style:"color:var(--ok)"},"已应用。"), " 网络正常的话请点“保留”，否则 ", left, "。");
      foot.replaceChildren(
        h("button",{class:"btn d",onclick:async()=>{ clearInterval(tick); await api("revert",{}).catch(()=>{}); m.remove(); toast("正在回滚…",4000); setTimeout(async()=>{await loadConfig(); show(S.page);},5000); }},"立即回滚"),
        h("button",{class:"btn p",onclick:async()=>{ clearInterval(tick); await api("confirm",{}); m.remove(); toast("已保留新配置"); await loadConfig(); show(S.page); }},"保留"));
    }
  };
  poll();
}

// ---------- login ----------
function renderLogin(setup){
  clearInterval(S.timer);
  const p = h("input",{type:"password",autocomplete:setup?"new-password":"current-password",placeholder:"密码"});
  const p2 = setup ? h("input",{type:"password",autocomplete:"new-password",placeholder:"再次输入"}) : null;
  const err = h("div",{class:"err"});
  const go = async e=>{ e.preventDefault(); err.textContent="";
    if (setup && p.value!==p2.value) return err.textContent="两次输入不一致";
    try { await api(setup?"setup":"login",{password:p.value}); boot(); } catch(x){ err.textContent=x.message; } };
  $("#root").replaceChildren(h("div",{class:"login"}, h("div",{class:"logo"}, logo(40), "Mini-Router"), h("form",{onsubmit:go}, card(setup?"设置管理员密码":"登录",
    [setup?h("div",{class:"mut"},"首次使用：请设置管理员密码（至少 8 位，只能在内网设置）。"):null, p, p2, err, h("button",{class:"btn p",type:"submit"}, setup?"设置并登录":"登录")]))));
  p.focus();
}

async function boot(){
  let s;
  try { s = await api("session"); } catch(e){ $("#root").replaceChildren(h("div",{class:"login"},h("div",{class:"err"},"无法连接路由器："+e.message))); return; }
  if (!s.authenticated) return renderLogin(!s.password_set);
  S.auth = true;
  renderShell();
  try { await loadConfig(); } catch(e){ toast("读取配置失败："+e.message, 5000); }
  show(location.hash.slice(1)||"overview");
}
window.addEventListener("DOMContentLoaded", boot);
