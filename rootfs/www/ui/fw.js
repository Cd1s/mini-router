// mini-router web UI — fw module pages (group firewall): 常规/安全, 端口转发, IPv6 入站, 通信规则, 设备管控.
// Uses only the helpers in ui/core.js; see docs/MODULES.md and docs/modules/fw.md.
"use strict";
(()=>{
addCSS(`
.fw-days{display:flex;gap:2px;flex-wrap:wrap}
.fw-days label{display:inline-flex;align-items:center;justify-content:center;min-width:30px;height:26px;border:1px solid var(--line);border-radius:4px;cursor:pointer;font-size:12px;user-select:none}
.fw-days label.on{background:var(--acc);border-color:var(--acc);color:var(--acc-fg)}
.fw-days input{display:none}
.fw-win{display:flex;gap:6px;align-items:center;flex-wrap:wrap;padding:6px 0;border-bottom:1px dashed var(--line)}
.fw-win input[type=text]{width:130px}
.fw-ops{white-space:nowrap;width:1%}
.fw-off td:not(.fw-keep){opacity:.45}
.fw-list li{margin:3px 0}
.fw-hits{font-variant-numeric:tabular-nums;white-space:nowrap}
`);

// ---------- shared bits ----------
const F = ()=>{ const f = S.cfg.firewall; for (const k of ["forwards","open","ipv6_allow","rules","access"]) f[k] ||= []; return f; };
const isOn = x => x.enabled !== false;
const DAYS = [["mon","一"],["tue","二"],["wed","三"],["thu","四"],["fri","五"],["sat","六"],["sun","日"]];
const ZONES = {"":"任意", lan:"LAN", guest:"访客", wan:"WAN", router:"路由器本机"};
const ACTIONS = {accept:["允许","ok"], drop:["丢弃","bad"], reject:["拒绝","warn"]};
const mono = s => h("span",{class:"mono"}, s);
const dash = v => (v===undefined || v===null || v==="" || (Array.isArray(v) && !v.length)) ? h("span",{class:"mut"},"—") : v;
const joinL = a => (a||[]).join(", ");
const wanIf = w => w.proto==="pppoe" ? "pppoe-"+w.name : w.device;

function onSwitch(x){
  return h("label",{class:"sw"}, h("input",{type:"checkbox", checked:isOn(x), onchange:e=>{ x.enabled=e.target.checked; touch(); e.target.closest("tr")?.classList.toggle("fw-off", !e.target.checked); }}), h("span"));
}
// drop empty optional keys so router.yaml stays tidy (the backend treats missing = empty)
function prune(o, keys){ for (const k of keys){ const v=o[k]; if (v===undefined || v==="" || v===null || (Array.isArray(v) && !v.length)) delete o[k]; } return o; }

// WAN subset picker: nothing ticked = all WANs
function wanPick(o){
  const wans = S.cfg.wan.map(w=>w.name);
  const box = h("span",{class:"row"});
  const draw = ()=>{
    const sel = new Set(o.wan||[]);
    box.replaceChildren(...wans.map(n=>h("label",{}, h("input",{type:"checkbox", checked:sel.has(n), onchange:e=>{
      e.target.checked ? sel.add(n) : sel.delete(n); o.wan = wans.filter(x=>sel.has(x)); touch(); }}), " "+n)),
      h("span",{class:"mut"}, "（都不选 = 全部 WAN）"));
  };
  draw(); return box;
}
function protoPick(o, key, list){
  o[key] ||= [];
  return h("span",{class:"row"}, list.map(p=>h("label",{}, h("input",{type:"checkbox", checked:o[key].includes(p), onchange:e=>{
    const s=new Set(o[key]); e.target.checked?s.add(p):s.delete(p); o[key]=list.filter(x=>s.has(x)); touch(); }}), " "+p.toUpperCase())));
}
function daysPick(win){
  const box = h("span",{class:"fw-days"});
  const draw = ()=>{
    const sel = new Set(win.days||[]);
    box.replaceChildren(...DAYS.map(([k,l])=>h("label",{class:sel.has(k)?"on":"", title:k}, h("input",{type:"checkbox", checked:sel.has(k), onchange:e=>{
      e.target.checked?sel.add(k):sel.delete(k); win.days = DAYS.map(d=>d[0]).filter(x=>sel.has(x)); touch(); draw(); }}), l)));
  };
  draw(); return box;
}
// weekly windows editor: [{days:[...], time:"HH:MM-HH:MM"}]
function schedEdit(o, key){
  o[key] ||= [];
  const box = h("div");
  const draw = ()=>{
    box.replaceChildren(...o[key].map((w,i)=>h("div",{class:"fw-win"}, daysPick(w),
        inText(w,"time",{placeholder:"22:00-07:00"}),
        h("button",{class:"btn sm d",onclick:()=>{ o[key].splice(i,1); touch(); draw(); }},"删除"))),
      h("div",{class:"row",style:"margin-top:6px"}, h("button",{class:"btn sm",onclick:()=>{ o[key].push({days:[],time:""}); touch(); draw(); }},"+ 时间段"),
        h("span",{class:"mut"}, o[key].length?"":"（无时间段 = 一直生效）")));
  };
  draw(); return box;
}
function schedText(sch){
  if (!sch || !sch.length) return "";
  const dn = Object.fromEntries(DAYS);
  return sch.map(w=>{
    const d = (w.days||[]).length===7 || !(w.days||[]).length ? "每天" : "周"+w.days.map(x=>dn[x]).join("");
    return d+" "+(w.time||"全天");
  }).join("；");
}
function hits(ctr, key){
  const c = ctr && ctr[key];
  return c ? h("span",{class:"fw-hits",title:fmtBytes(c.bytes)}, c.packets+" 包") : h("span",{class:"mut"},"—");
}
async function stats(){ try { return await api("fw.stats"); } catch(e){ return {counters:{}, log:[]}; } }
async function knownDevices(){
  const m = new Map();
  for (const x of S.cfg.dhcp.hosts||[]) m.set((x.mac||"").toLowerCase(), {name:x.name, ip:x.ip, mac:(x.mac||"").toLowerCase()});
  try { for (const l of (await api("status")).leases||[]) { const k=l.mac.toLowerCase(); if(!m.has(k)) m.set(k, {name:l.name==="*"?"":l.name, ip:l.ip, mac:k}); } } catch(e){}
  return [...m.values()];
}
function devName(devs, mac){ const d = devs.find(x=>x.mac===String(mac).toLowerCase()); return d && d.name ? d.name : ""; }

// modal editor: edits a copy, writes it back only on 确定
function editDlg(title, orig, build, save){
  const o = clone(orig);
  const m = modal(title, build(o), [
    h("button",{class:"btn",onclick:()=>m.remove()},"取消"),
    h("button",{class:"btn p",onclick:()=>{ if(!String(o.name||"").trim()) return toast("请填写名称"); save(o); m.remove(); touch(); }},"确定")]);
}
// list card: enabled switch, summary columns, ↑ / 编辑 / 删除, "+ 添加" opens the editor
function listCard(title, arr, cols, o){
  const tb = h("tbody");
  const draw = ()=>{
    tb.replaceChildren();
    if (!arr.length) tb.append(h("tr",{}, h("td",{colspan:cols.length+2, class:"mut"}, "（空）")));
    arr.forEach((x,i)=>tb.append(h("tr",{class:isOn(x)?"":"fw-off"},
      h("td",{class:"fw-keep",style:"width:1%"}, onSwitch(x)),
      cols.map(c=>h("td",{}, dash(c.f(x,i)))),
      h("td",{class:"fw-ops fw-keep"},
        o.order ? h("button",{class:"btn sm",title:"上移",disabled:i===0,onclick:()=>{ [arr[i-1],arr[i]]=[arr[i],arr[i-1]]; touch(); draw(); }},"↑") : null, " ",
        h("button",{class:"btn sm",onclick:()=>o.edit(x, v=>{ arr[i]=v; draw(); })},"编辑"), " ",
        h("button",{class:"btn sm d",onclick:()=>{ if(confirm("删除 "+(x.name||"")+"？")){ arr.splice(i,1); touch(); draw(); } }},"删除")))));
  };
  draw();
  const add = h("button",{class:"btn sm p",onclick:()=>o.edit(o.blank(), v=>{ arr.push(v); draw(); })},"+ 添加");
  return card(title, [o.note ? h("div",{class:"mut",style:"padding:10px 16px 0"}, o.note) : null,
    h("div",{class:"tw"}, h("table",{}, h("thead",{}, h("tr",{}, h("th",{},"启用"), cols.map(c=>h("th",{},c.l)), h("th",{}))), tb))], add, true);
}

// ---------- 常规 / 安全 ----------
registerPage("firewall", "firewall", "常规 / 安全", 10, async ()=>{
  const c = S.cfg, f = F();
  const st = await stats();
  const lanIfs = [c.lan.bridge, ...c.networks.filter(n=>(n.zone||"guest")==="lan").map(n=>"br-"+n.name), "tailscale0"];
  const guestIfs = c.networks.filter(n=>(n.zone||"guest")==="guest").map(n=>"br-"+n.name);
  const wanIfs = c.wan.map(wanIf);
  const zones = roTable(["区域","接口","访问路由器","转发"], [
    [h("b",{},"lan"), mono(lanIfs.join(" ")), "全部允许（含管理界面）", "任意"],
    [h("b",{},"guest"), guestIfs.length?mono(guestIfs.join(" ")):h("span",{class:"mut"},"（无访客网络）"), "仅 DHCP / DNS / ICMP", "仅 WAN"],
    [h("b",{},"wan"), mono(wanIfs.join(" ")), "仅已建立连接、开放端口、tailscale、必要 ICMP", "仅已建立连接、端口转发、IPv6 入站规则"]]);

  // exposure review (what the WAN can reach on the router right now, from the edited config)
  const sshPort = (c.services.ssh||{}).port||22;
  const inPorts = (p, want)=>String(p||"").split(",").some(x=>{ const [a,b]=x.trim().split("-").map(Number); return want>=a && want<=(b||a); });
  const exp = [h("li",{},"已建立 / 相关连接的回包")];
  if (f.wan_ping!==false) exp.push(h("li",{},"ICMPv4 ping（限速 20/秒）"));
  exp.push(h("li",{},"ICMPv6 必要报文（差错、邻居发现、MLD、ping 限速）、DHCPv6 客户端（仅链路本地）"));
  if ((c.services.tailscale||{}).enabled) exp.push(h("li",{},"tailscale UDP "+((c.services.tailscale||{}).port||41641)));
  const edge = c.services.edge||{};
  if (edge.enabled && edge.open) exp.push(h("li",{}, "HTTPS 反向代理 TCP "+(edge.port||443)+" · "+(edge.routes||[]).filter(isOn).length+" 个站点",
    h("span",{class:"mut"}," （服务 › HTTPS 反向代理；每个站点可限制来源）")));
  for (const o of f.open.filter(isOn)){
    const warn = [];
    if (inPorts(o.port, sshPort) && (o.proto||[]).includes("tcp")) warn.push("SSH");
    if (inPorts(o.port, 80) && (o.proto||[]).includes("tcp")) warn.push("管理界面");
    exp.push(h("li",{}, (o.proto||[]).join("/").toUpperCase()+" "+o.port+" · "+o.name, (o.src_ip||[]).length?h("span",{class:"mut"}," （仅 "+joinL(o.src_ip)+"）"):null,
      warn.length?[" ", h("span",{class:"tag bad"},"⚠ 暴露"+warn.join("、"))]:null));
  }
  const nf = f.forwards.filter(isOn).length, n6 = f.ipv6_allow.filter(isOn).length;
  const ruleAccept = f.rules.filter(r=>isOn(r) && r.action==="accept" && (r.src||"")!=="lan" && (r.src||"")!=="guest").length;

  const openCard = listCard("开放路由器端口（WAN → 路由器）", f.open, [
      {l:"名称", f:x=>x.name}, {l:"协议", f:x=>joinL(x.proto).toUpperCase()}, {l:"端口", f:x=>mono(x.port)},
      {l:"WAN", f:x=>joinL(x.wan)||"全部"}, {l:"来源", f:x=>joinL(x.src_ip)||"任意"}, {l:"说明", f:x=>x.desc}],
    {blank:()=>({name:"", enabled:true, proto:["tcp"], port:""}),
     edit:(x,save)=>editDlg("开放路由器端口", x, o=>form(
        ...field("名称", inText(o,"name",{placeholder:"lucky-https"})),
        ...field("协议", inProto(o,"proto")),
        ...field("端口", inText(o,"port",{placeholder:"443 或 8000-8100 或 80,443"})),
        ...field("WAN", wanPick(o)),
        ...field("来源限制", inList(o,"src_ip",{placeholder:"留空 = 任意；例如 203.0.113.0/24, 2001:db8::/32"}), "IPv4 / IPv6 地址或网段"),
        ...field("说明", inText(o,"desc"))), o=>save(prune(o,["wan","src_ip","desc"]))),
     note:"给路由器本身的服务（如 lucky 443）开放外网访问，IPv4 与 IPv6 同时生效。SSH 与管理界面不要开放，远程管理请走 tailscale。"});

  const logBox = h("pre",{}, (st.log||[]).slice(-50).join("\n") || (f.log_drops ? "（暂无记录）" : "（未开启日志）"));
  const dropped = (st.counters||{})["wan-in-drop"];
  return h("div",{},
    card("防火墙与加速", form(
      ...field("流量卸载", inSel(f,"offload",[["hardware","硬件加速（PPE + WED）"],["software","软件快速转发"],["off","关闭"]]), "已建立的连接由 PPE / WED 直接转发，不经过 CPU；设备管控里的设备除外"),
      ...field("SYN 洪水防护", inBool(f,"synflood_protect"), "发往路由器的新 TCP 连接超过 50/秒时丢弃"),
      ...field("允许 WAN ping (IPv4)", inBool(f,"wan_ping"), "关闭后外网 ping 不通路由器 IPv4；IPv6 必要 ICMP 始终放行"),
      ...field("丢弃无效连接", inBool(f,"drop_invalid"), "丢弃 conntrack 判定为 invalid 的包（建议开启）"),
      ...field("记录 WAN 入站拦截", inBool(f,"log_drops"), "限速写入内核日志（10 条/分钟），需要内核 nf_log 模块"))),
    card("区域", zones, null, true),
    openCard,
    card("对外暴露检查", [h("div",{class:"mut",style:"margin-bottom:6px"},"外网（WAN）能直接到达路由器的只有："), h("ul",{class:"fw-list",style:"margin:0;padding-left:20px"}, exp),
      h("div",{class:"mut",style:"margin-top:8px"}, "另外：端口转发 "+nf+" 条、IPv6 入站 "+n6+" 条、来源可能是 WAN 的允许规则 "+ruleAccept+" 条（到内网主机，不到路由器）。访客网络只能用 DHCP / DNS / ICMP，访问不到管理界面。")]),
    card("拦截统计", [h("div",{class:"row",style:"margin-bottom:8px"}, "WAN 入站已拦截：", h("b",{}, dropped?dropped.packets+" 包（"+fmtBytes(dropped.bytes)+"）":"—"),
      st.error?h("span",{class:"tag warn"}, st.error):null), logBox],
      h("button",{class:"btn sm",onclick:()=>show("firewall")},"刷新")));
});

// ---------- 端口转发 ----------
registerPage("firewall", "forward", "端口转发", 20, async ()=>{
  const f = F();
  const devs = await knownDevices();
  const ipList = "fw-hosts";
  const dl = h("datalist",{id:ipList}, devs.filter(d=>d.ip).map(d=>h("option",{value:d.ip}, d.name||d.mac)));
  return h("div",{}, dl, listCard("端口转发（IPv4 DNAT）", f.forwards, [
      {l:"名称", f:x=>x.name}, {l:"协议", f:x=>joinL(x.proto).toUpperCase()}, {l:"外部端口", f:x=>mono(x.port)},
      {l:"内部地址", f:x=>mono(x.to+(x.to_port&&x.to_port!==x.port?":"+x.to_port:""))},
      {l:"WAN", f:x=>joinL(x.wan)||"全部"}, {l:"来源", f:x=>joinL(x.src_ip)||"任意"}, {l:"说明", f:x=>x.desc}],
    {blank:()=>({name:"", enabled:true, proto:["tcp"], port:"", to:"", to_port:""}),
     edit:(x,save)=>editDlg("端口转发", x, o=>form(
        ...field("名称", inText(o,"name",{placeholder:"nas-https"})),
        ...field("协议", inProto(o,"proto")),
        ...field("外部端口", inText(o,"port",{placeholder:"8080 或 1000-2000"})),
        ...field("内部 IP", inText(o,"to",{placeholder:"192.168.1.x", list:ipList}), "必须在某个内网 / 访客网络之内"),
        ...field("内部端口", inText(o,"to_port",{placeholder:"留空 = 同外部端口"}), "端口段只能映射到相同端口段或单个端口"),
        ...field("WAN", wanPick(o)),
        ...field("来源限制", inList(o,"src_ip",{placeholder:"留空 = 任意；例如 203.0.113.0/24"}), "只允许这些 IPv4 地址 / 网段访问"),
        ...field("说明", inText(o,"desc"))), o=>save(prune(o,["wan","src_ip","desc"]))),
     note:"自动带 NAT 回流：内网设备用公网 IP 也能访问。转发到访客网络的主机也可以（目标必须在该网络内）。"}),
    card("说明", h("div",{class:"mut"}, "端口转发只对 IPv4 生效；IPv6 没有 NAT，请在“IPv6 入站”里放行。停用的条目保留配置但不生效。")));
});

// ---------- IPv6 入站 ----------
const eui64 = mac=>{
  const b = String(mac||"").split(":").map(x=>parseInt(x,16));
  if (b.length!==6 || b.some(x=>isNaN(x))) return "";
  const g = [((b[0]^2)<<8)|b[1], (b[2]<<8)|0xff, 0xfe00|b[3], (b[4]<<8)|b[5]];
  while (g.length>1 && g[0]===0) g.shift();
  return "::"+g.map(x=>x.toString(16)).join(":");
};
registerPage("firewall", "ipv6in", "IPv6 入站", 30, async ()=>{
  const f = F();
  const st = await stats();
  const [devs] = await Promise.all([knownDevices()]);
  const target = x=> x.mac ? h("span",{}, mono(eui64(x.mac)), h("span",{class:"mut"}," ← "+(devName(devs,x.mac)||x.mac))) : mono(x.iid||"");
  return h("div",{}, listCard("IPv6 入站放行（WAN → 内网主机）", f.ipv6_allow, [
      {l:"名称", f:x=>x.name}, {l:"目标主机（接口标识）", f:target}, {l:"协议", f:x=>joinL(x.proto).toUpperCase()}, {l:"端口", f:x=>mono(x.port)},
      {l:"来源", f:x=>joinL(x.src_ip)||"任意"}, {l:"WAN", f:x=>joinL(x.wan)||"全部"}, {l:"命中", f:x=>hits(st.counters,"v6in:"+x.name)}],
    {blank:()=>({name:"", enabled:true, iid:"", proto:["tcp"], port:""}),
     edit:(x,save)=>editDlg("IPv6 入站放行", x, o=>{
        const how = {m: o.mac ? "mac" : "iid"};
        const slot = h("div",{style:"display:contents"});
        const hint = h("span",{class:"mono"});
        const drawSlot = ()=>{
          if (how.m==="mac"){ delete o.iid; o.mac ||= ""; hint.textContent = eui64(o.mac) || "";
            slot.replaceChildren(...field("MAC", h("input",{type:"text", value:o.mac, placeholder:"aa:bb:cc:dd:ee:ff", list:"fw-macs", oninput:e=>{ o.mac=e.target.value.trim(); hint.textContent=eui64(o.mac); touch(); }}),
              h("span",{}, "按 EUI-64 推导接口标识：", hint))); }
          else { delete o.mac; o.iid ||= "";
            slot.replaceChildren(...field("接口标识 (IID)", inText(o,"iid",{placeholder:"::10 或 ::211:32ff:fe12:3456"}), "地址的后 64 位，前缀变了也不用改规则")); }
        };
        drawSlot();
        return h("div",{}, h("datalist",{id:"fw-macs"}, devs.map(d=>h("option",{value:d.mac}, (d.name||"")+" "+(d.ip||"")))), form(
          ...field("名称", inText(o,"name",{placeholder:"nas-https"})),
          ...field("匹配方式", inSel(how,"m",[["iid","固定接口标识（推荐）"],["mac","由 MAC 推导 (EUI-64)"]], ()=>drawSlot())),
          slot,
          ...field("协议", inProto(o,"proto")),
          ...field("端口", inText(o,"port",{placeholder:"443 或 8000-8100 或 80,443"})),
          ...field("来源限制", inList(o,"src_ip",{placeholder:"留空 = 任意；例如 2001:db8::/32"}), "只允许这些 IPv6 地址 / 网段"),
          ...field("WAN", wanPick(o)),
          ...field("说明", inText(o,"desc"))));
      }, o=>save(prune(o,["wan","src_ip","desc","iid","mac"]))),
     note:"IPv6 没有 NAT，公网可直接访问内网主机的地址，默认全部拦截。这里按“接口标识”（地址后 64 位）放行，运营商换前缀后规则依然有效。"}),
    card("怎么让主机有固定的接口标识", h("ul",{class:"fw-list",style:"margin:0;padding-left:20px"},
      h("li",{}, "Linux（NetworkManager）：", mono("nmcli con mod <连接> ipv6.addr-gen-mode eui64"), " 或设置 ", mono("ipv6.token ::10")),
      h("li",{}, "Linux（ip 命令）：", mono("ip token set ::10 dev eth0")),
      h("li",{}, "macOS / Windows / 手机默认用随机标识，不适合做服务器；请在主机上固定标识或用 EUI-64。"),
      h("li",{}, "ICMPv6 ping 与差错报文对内网主机始终放行（IPv6 正常工作需要）。"))));
});

// ---------- 通信规则 ----------
registerPage("firewall", "fwrules", "通信规则", 40, async ()=>{
  const f = F();
  const st = await stats();
  const side = (z, ip, mac)=>{
    const parts = [ZONES[z||""]||z];
    if ((ip||[]).length) parts.push(joinL(ip));
    if ((mac||[]).length) parts.push(joinL(mac));
    return parts.join(" · ");
  };
  return h("div",{}, listCard("通信规则（按顺序匹配，先中先停）", f.rules, [
      {l:"#", f:(x,i)=>i+1},
      {l:"名称", f:x=>x.name},
      {l:"动作", f:x=>{ const a=ACTIONS[x.action]||[x.action,""]; return h("span",{class:"tag "+a[1]}, a[0]); }},
      {l:"源", f:x=>side(x.src, x.src_ip, x.src_mac)},
      {l:"目标", f:x=>side(x.dest, x.dest_ip)},
      {l:"协议 / 端口", f:x=>(x.proto||[]).length ? joinL(x.proto).toUpperCase()+(x.dest_port?" "+x.dest_port:"") : "任意"},
      {l:"时间", f:x=>schedText(x.schedule)||"始终"},
      {l:"命中", f:x=>x.counter ? hits(st.counters,"rule:"+x.name) : h("span",{class:"mut"},"未计数")}],
    {order:true,
     blank:()=>({name:"", enabled:true, action:"drop", src:"lan", dest:"wan", counter:true}),
     edit:(x,save)=>editDlg("通信规则", x, o=>form(
        ...field("名称", inText(o,"name",{placeholder:"block-smtp"})),
        ...field("动作", inSel(o,"action",[["accept","允许 (accept)"],["drop","丢弃 (drop)"],["reject","拒绝 (reject，立即告知对方)"]])),
        ...field("源区域", inSel(o,"src",[["","任意"],["lan","LAN"],["guest","访客"],["wan","WAN"]])),
        ...field("源地址", inList(o,"src_ip",{placeholder:"192.168.1.50, 192.168.1.0/28, 2001:db8::/64"})),
        ...field("源 MAC", inList(o,"src_mac",{placeholder:"aa:bb:cc:dd:ee:ff"}), "仅对内网侧来源有效"),
        ...field("目标区域", inSel(o,"dest",[["","任意（转发）"],["lan","LAN"],["guest","访客"],["wan","WAN"],["router","路由器本机"]]), "路由器本机只能丢弃 / 拒绝；开放端口请用“常规 / 安全”页"),
        ...field("目标地址", inList(o,"dest_ip",{placeholder:"留空 = 任意"})),
        ...field("协议", protoPick(o,"proto",["tcp","udp","icmp"]), "都不选 = 任意协议"),
        ...field("目标端口", inText(o,"dest_port",{placeholder:"25 或 8000-8100 或 80,443（需选 TCP/UDP）"})),
        ...field("生效时间", schedEdit(o,"schedule"), "按系统时区；跨午夜（如 22:00-07:00）自动算到次日"),
        ...field("计数", inBool(o,"counter")),
        ...field("日志", inBool(o,"log"), "限速写入内核日志，前缀 mr-rule"),
        ...field("说明", inText(o,"desc"))), o=>save(prune(o,["src","dest","src_ip","src_mac","dest_ip","proto","dest_port","schedule","desc"]))),
     note:"规则在区域默认策略之前匹配，只作用于新建连接。目标为“路由器本机”的规则在 LAN 放行之前生效，可用来限制某台设备访问路由器服务。"}));
});

// ---------- 设备管控 ----------
registerPage("firewall", "access", "设备管控", 50, async ()=>{
  const f = F();
  const [st, devs] = await Promise.all([stats(), knownDevices()]);
  const macsText = x=>(x.macs||[]).map(m=>{ const n=devName(devs,m); return n ? n+" ("+m+")" : m; }).join(", ");
  return h("div",{}, listCard("禁止上网的设备", f.access, [
      {l:"名称", f:x=>x.name},
      {l:"设备", f:x=>mono(macsText(x))},
      {l:"禁止时间", f:x=>schedText(x.schedule)||h("span",{class:"tag bad"},"始终禁止")},
      {l:"已拦截", f:x=>hits(st.counters,"access:"+x.name)},
      {l:"说明", f:x=>x.desc}],
    {blank:()=>({name:"", enabled:true, macs:[]}),
     edit:(x,save)=>editDlg("设备管控", x, o=>{
        const mode = {m: (o.schedule||[]).length ? "sched" : "always"};
        const schedSlot = h("div",{style:"display:contents"});
        const macIn = inList(o,"macs",{placeholder:"aa:bb:cc:dd:ee:ff, …"});
        const pick = h("select",{onchange:e=>{ const v=e.target.value; if(!v) return; o.macs ||= []; if(!o.macs.includes(v)) o.macs.push(v); macIn.value=o.macs.join(", "); e.target.value=""; touch(); }},
          h("option",{value:""},"从已知设备添加…"), devs.map(d=>h("option",{value:d.mac}, (d.name||"未命名")+" · "+(d.ip||"")+" · "+d.mac)));
        const drawSched = ()=>{
          if (mode.m==="always"){ o.schedule=[]; schedSlot.replaceChildren(); }
          else { if(!(o.schedule||[]).length) o.schedule=[{days:["sun","mon","tue","wed","thu"],time:"22:00-07:00"}];
            schedSlot.replaceChildren(...field("禁止时间段", schedEdit(o,"schedule"), "按系统时区；跨午夜自动算到次日")); }
        };
        drawSched();
        return form(
          ...field("名称", inText(o,"name",{placeholder:"kid-ipad"})),
          ...field("设备 MAC", h("div",{style:"display:grid;gap:6px"}, macIn, pick), "可填多个；手机请关闭该 WiFi 的“私有地址”或填它在本网络使用的 MAC"),
          ...field("模式", inSel(mode,"m",[["always","始终禁止上网"],["sched","按时间段禁止"]], ()=>drawSched())),
          schedSlot,
          ...field("说明", inText(o,"desc")));
      }, o=>save(prune(o,["schedule","desc"]))),
     note:"只禁止访问外网（WAN），内网、DHCP、DNS 照常。到点立即生效，已建立的连接也会断开——为此这些设备的流量不走硬件加速。"}));
});
})();
