// mini-router web UI — net module pages. Uses the helpers in ui/core.js; see docs/MODULES.md.
// Pages: 接口状态 (status), WAN 外网 / 多线路 / LAN 与网络 / IPv6 (network), 静态路由 / 策略路由 / 组播 (routing).
"use strict";
(()=>{
addCSS(`
.net-ports{display:flex;gap:10px;flex-wrap:wrap}
.net-port{width:76px;border:1px solid var(--line);border-radius:6px;background:var(--code);text-align:center;padding:7px 4px 6px;font-size:12px}
.net-port .jack{height:24px;width:36px;margin:0 auto 6px;border-radius:3px 3px 7px 7px;background:var(--line)}
.net-port.up .jack{background:var(--ok)}
.net-port.slow .jack{background:var(--warn)}
.net-port b{display:block}
.net-port .s{color:var(--mut);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.net-rt{font-size:12px;color:var(--mut);padding:0 0 12px}
.net-chk{display:flex;gap:4px 12px;flex-wrap:wrap}
.net-chk label{white-space:nowrap}
`);

const PROTOS = [["pppoe","PPPoE 拨号"],["dhcp","DHCP 自动获取"],["static","静态地址"]];
const fmtSpeed = s => !s ? "" : s>=1000 ? (s/1000)+"G" : s+"M";
const natSort = a => a.slice().sort((x,y)=>x.localeCompare(y, undefined, {numeric:true}));
const mono = x => h("span",{class:"mono"}, x);
const healthTag = w => !w || !w.health ? null : h("span",{class:"tag "+(w.health==="up"?"ok":"bad")}, w.health==="up"?"健康":"故障");
const svcOf = w => w.proto==="pppoe" ? "mr-pppoe."+w.name : w.proto==="dhcp" ? "mr-udhcpc."+w.name : "";
async function portNames(){
  let ports = [];
  try { ports = ((await api("net.ports")).ports||[]).filter(p=>p.kind==="port").map(p=>p.name); } catch(e){}
  const c = S.cfg;
  return natSort([...new Set([...ports, ...c.lan.ports, ...c.networks.flatMap(n=>[...(n.ports||[]), ...(n.trunk||[])]), ...c.wan.map(w=>w.device).filter(Boolean)])]);
}
function checks(list, isOn, toggle, disabled){
  return h("span",{class:"net-chk"}, list.length ? list.map(p=>h("label",{}, h("input",{type:"checkbox", checked:isOn(p), disabled:disabled?disabled(p):false,
    onchange:e=>{ toggle(p, e.target.checked); touch(); }}), " "+p)) : h("span",{class:"mut"},"（无）"));
}
async function wanRuntime(){ try { return await api("net.wan"); } catch(e){ return {wans:[]}; } }

// ---------- travel: captive portal, WAN / LAN subnet conflict, NAT upstream ----------
// (overview notices + the WAN / LAN pages; backend: mr/mod_net_travel.go)
const CHECK_TXT = {online:"在线", portal:"需要网页登录", offline:"不通"};
const CHECKING = {};
async function runCheck(name){
  CHECKING[name] = true;
  try { const r = await api("net.check",{wan:name}); toast(name+"："+(CHECK_TXT[r.state]||r.state)+(r.error?"（"+r.error+"）":""), 5000); return r; }
  catch(e){ toast(e.message, 4000); }
  finally { delete CHECKING[name]; }
}
const checkBtn = (name, label, after)=>h("button",{class:"btn sm", disabled:!!CHECKING[name], onclick:async e=>{
  e.target.disabled = true; e.target.textContent = "检测中…"; await runCheck(name); if (after) after(); }}, CHECKING[name] ? "检测中…" : (label||"重新检测"));
// the login page: what the portal named, else the check URL itself (the portal intercepts it)
const portalLink = k=>(k.portal_url||k.url) ? h("a",{class:"btn sm p", href:k.portal_url||k.url, target:"_blank", rel:"noopener noreferrer"}, "打开登录页") : null;
function rebindHint(k){
  let host = ""; try { host = new URL(k.portal_url||"").hostname; } catch(e){}
  if (!host || /^[0-9.]+$/.test(host) || !(S.cfg && S.cfg.dns && S.cfg.dns.rebind_protection)) return null;
  return h("span",{class:"mut"}, " 登录页打不开时：门户域名常解析到私网地址，会被“DNS 重绑定保护”拦下，可以在 DNS 页暂时关掉它。");
}
const netName = x=>x.network==="lan" ? "LAN" : "网络 "+x.network;
const hasInbound = ()=>!!(S.cfg && S.cfg.firewall && ((S.cfg.firewall.forwards||[]).length || (S.cfg.firewall.open||[]).length));
registerNotice(s=>(s.wan||[]).flatMap(w=>{
  const out = [], k = w.check, x = w.conflict;
  if (x) out.push(notice("bad", [h("b",{},"WAN "+w.name+" 与局域网网段冲突："), "上级网络分配的 ", mono(x.lease), " 和 "+netName(x)+" ", mono(x.net),
    " 重叠，为了不把局域网一起弄断，这个地址没有启用。把 "+netName(x)+" 改到别的网段", x.suggest ? ["（例如 ", mono(x.suggest), "）"] : null, "并应用后，会自动重新获取地址。"],
    h("a",{class:"btn sm p", href:"#lan"}, "修改网段")));
  if (w.up && k && k.state==="portal") out.push(notice("warn", [h("b",{},"WAN "+w.name+" 需要网页登录"),
    "（酒店 / 机场的门户认证）。在任意一台连着本路由器的设备上打开登录页完成认证即可：认证的是路由器，其它设备随之可用。", rebindHint(k)],
    portalLink(k), checkBtn(w.name, "我已登录，重新检测")));
  if (w.up && k && k.state==="offline") out.push(notice("warn", [h("b",{},"WAN "+w.name+" 有地址但上不了网"), "（连通性检测："+(k.error||"没有响应")+"）。"], checkBtn(w.name)));
  const nk = "nat:"+w.name+":"+w.ip;
  if (w.up && w.addr_class && hasInbound() && !dismissed(nk)) out.push(notice("info", ["WAN "+w.name+" 的地址 ", mono(w.ip),
    w.addr_class==="cgnat" ? " 是运营商级 NAT（CGNAT，100.64.0.0/10）" : " 是私网地址（上级还有一层路由器）",
    "：端口转发和从外网访问路由器的 IPv4 规则在这条线路上不起作用。"], dismissBtn(nk)));
  return out;
}));
// one WAN's travel state for the WAN page status line
function travelTags(r, redraw){
  const k = r.check, x = r.conflict, out = [];
  if (x) out.push(" · ", h("span",{class:"tag bad", title:"和 "+netName(x)+" "+x.net+" 重叠，没有启用"}, "地址冲突 "+x.lease));
  if (k) out.push(" · ", h("span",{class:"tag "+(k.state==="online"?"ok":k.state==="portal"?"warn":"bad"),
    title: k.error || (k.url ? k.url+" → HTTP "+k.code+(k.rtt_ms!=null?"，"+k.rtt_ms+" ms":"") : "")}, CHECK_TXT[k.state]||k.state),
    k.state==="portal" ? [" ", portalLink(k)] : null);
  if (r.addr_class) out.push(" · ", h("span",{class:"tag", title:"上级还有一层 NAT：端口转发 / IPv4 入站在这条线路上不可用"}, r.addr_class==="cgnat" ? "CGNAT" : "私网地址"));
  if (r.up) out.push(" ", checkBtn(r.name, "检测", redraw));
  return out;
}

// ---------- 接口状态 ----------
registerPage("status", "interfaces", "接口状态", 30, async ()=>{
  const panel = h("div",{class:"net-ports"}), list = h("div"), when = h("span",{class:"mut",style:"font-weight:400;font-size:12px"});
  let prev = null;
  const draw = async ()=>{
    const j = await api("net.ports"), ports = j.ports||[], now = j.time||Date.now();
    const rate = {};
    if (prev && now>prev.t) for (const p of ports){ const o=prev.m[p.name]; if (o) rate[p.name] = {rx:Math.max(0,(p.rx_bytes-o.rx_bytes)*8000/(now-prev.t)), tx:Math.max(0,(p.tx_bytes-o.tx_bytes)*8000/(now-prev.t))}; }
    prev = {t:now, m:Object.fromEntries(ports.map(p=>[p.name,p]))};
    const phys = ports.filter(p=>p.kind==="port");
    panel.replaceChildren(...(phys.length ? phys.map(p=>h("div",{class:"net-port"+(p.carrier?(p.speed&&p.speed<1000?" slow":" up"):""),
        title: p.name+(p.carrier?" · "+(p.speed?p.speed+" Mbit/s ":"")+(p.duplex||""):" · 未连接")},
      h("div",{class:"jack"}), h("b",{}, p.name.toUpperCase()),
      h("div",{class:"s"}, p.carrier ? (fmtSpeed(p.speed)||"已连接")+(p.duplex==="half"?" 半双工":"") : "未连接"),
      h("div",{class:"s"}, p.role||"未使用"))) : [h("span",{class:"mut"},"（没有检测到物理网口）")]));
    const kinds = {port:"网口",cpu:"CPU 口",bridge:"网桥",vlan:"VLAN",ppp:"PPPoE",wifi:"WiFi",tunnel:"隧道",other:"其它"};
    list.replaceChildren(roTable(["接口","类型","用途","状态","速率","MTU","MAC","上级","实时 ↓ / ↑","累计 ↓ / ↑","错误 / 丢弃"], ports.map(p=>{
      const ok = p.admin_up && (p.carrier || p.oper==="up" || p.oper==="unknown");
      const r = rate[p.name];
      return [h("span",{}, h("span",{class:"dot "+(ok?"ok":"bad")}), h("b",{}, p.name)), kinds[p.kind]||p.kind, p.role||"",
        p.admin_up ? (p.oper||"") : "已禁用", p.speed ? p.speed+"M "+(p.duplex==="half"?"半双工":"全双工") : "", p.mtu, mono(p.mac||""), p.master||"",
        r ? fmtRate(r.rx)+" / "+fmtRate(r.tx) : "…", fmtBytes(p.rx_bytes)+" / "+fmtBytes(p.tx_bytes),
        h("span",{class:(p.rx_errors+p.tx_errors)?"err":""}, (p.rx_errors+p.tx_errors)+" / "+(p.rx_dropped+p.tx_dropped))];
    })));
    when.textContent = "每 3 秒刷新";
  };
  await draw();
  S.timer = setInterval(()=>draw().catch(()=>{}), 3000);
  const neigh = async ()=>{
    const n = await api("net");
    return card("邻居表（ARP / NDP）", roTable(["地址","MAC","接口","状态"], (n.neigh||[]).filter(x=>x.lladdr).map(x=>[mono(x.dst), mono(x.lladdr), x.dev, (x.state||[]).join(",")])), null, true);
  };
  return h("div",{}, card("物理网口", panel, when),
    tabs([["if","全部接口", ()=>card("接口（速率由两次采样计算）", list, null, true)], ["neigh","邻居表", neigh]]));
});

// ---------- WAN ----------
registerPage("network", "wan", "WAN 外网", 10, async ()=>{
  const c = S.cfg;
  const [rt, ports] = await Promise.all([wanRuntime(), portNames()]);
  const live = Object.fromEntries((rt.wans||[]).map(w=>[w.name,w]));
  const dl = h("datalist",{id:"net-portlist"}, ports.map(p=>h("option",{value:p})));
  const box = h("div");
  const setProto = (w, p)=>{
    if (p!=="static"){ delete w.ipv4; delete w.gateway; delete w.dns; }
    if (p==="pppoe" && !w.mtu) w.mtu = 1492;
    if (p!=="pppoe" && w.mtu===1492) w.mtu = 0;
    draw();
  };
  const status = w=>{
    const r = live[w.name];
    if (!r) return h("div",{class:"net-rt"}, "（尚未应用）");
    const now = Date.now()/1000;
    return h("div",{class:"net-rt row"}, h("span",{class:"dot "+(r.up?"ok":"bad")}),
      r.up ? ["已连接 ", mono(r.ip), r.gateway?[" · 网关 ", mono(r.gateway)]:null, r.since?" · "+fmtDur(now-r.since):null, (r.dns||[]).length?" · DNS "+r.dns.join(", "):null] : "未连接",
      " · 接口 ", mono(r.dev), healthTag(r), travelTags(r, ()=>show("wan")));
  };
  const redial = w=>{
    if (!svcOf(w) || !live[w.name]) return null;
    return h("button",{class:"btn sm",onclick:async()=>{
      if (!confirm((w.proto==="pppoe"?"重新拨号 ":"重新获取地址 ")+w.name+"？这条线路会短暂断开。")) return;
      try { await api("net.redial",{wan:w.name}); toast("正在重连 "+w.name, 3000); } catch(e){ toast(e.message, 4000); } }}, w.proto==="pppoe"?"重新拨号":"重新获取");
  };
  const wanCard = (w, i)=>{
    const p = w.proto;
    const rows = [
      ...field("名称", inText(w,"name"), p==="pppoe" ? "PPPoE 接口为 pppoe-<名称>，最多 9 个字符" : "小写字母开头"),
      ...field("协议", inSel(w,"proto",PROTOS, v=>setProto(w,v))),
      ...field("物理接口", inText(w,"device",{placeholder:"wan", list:"net-portlist"}), "同一个网口可以跑多条 PPPoE（多拨）"),
      ...field("VLAN", inNum(w,"vlan",{min:0,max:4094}), "0 = 不打标签；运营商要求时填（例如 PPPoE 走 VLAN 500）"),
    ];
    if (p==="pppoe") rows.push(
      ...field("PPPoE 账号", inText(w,"username")),
      ...field("密码引用名", inText(w,"password_secret",{placeholder:"pppoe_password"}), "密码保存在 secrets.yaml，多条 WAN 可共用一个"),
      ...field("PPPoE 密码", inSecret(w,"password_secret")));
    if (p==="static") rows.push(
      ...field("IPv4 地址 / 掩码", inText(w,"ipv4",{placeholder:"203.0.113.10/24"})),
      ...field("网关", inText(w,"gateway",{placeholder:"203.0.113.1"})),
      ...field("DNS 服务器", inList(w,"dns",{placeholder:"1.1.1.1, 8.8.8.8"}), "最多 3 个，交给 dnsmasq 作为上游"));
    rows.push(
      ...field("克隆 MAC", inText(w,"mac",{placeholder:"留空使用默认"}), "作用于物理接口"),
      ...field("MTU", inNum(w,"mtu"), p==="pppoe" ? "PPPoE 一般 1492" : "0 = 不修改"),
      ...field("路由跃点 (metric)", inNum(w,"metric",{min:0,max:9999}), "越小越优先，每条 WAN 各不相同；主线路 0，备用线路更大（多线路按它主备切换）"));
    if (p!=="static") rows.push(...field("使用运营商 DNS", inBool(w,"peerdns")));
    rows.push(...field("门户 / 连通性检测", inSel(w,"portal",[["","默认（DHCP 开，PPPoE / 静态关）"],["auto","开"],["off","关"]]),
      "上线和续租时经这条线路访问一次 HTTP 检测地址：发现需要网页登录（酒店 / 机场）就在总览提示并把网络灯变黄；NTP 不通时顺便按响应的 Date 粗校时钟"));
    rows.push(
      ...field("IPv6", inBool(w,"ipv6"), "dhcpcd 获取 IPv6（RA / DHCPv6）"),
      ...field("请求 IPv6 前缀 (PD)", inBool(w,"ipv6_pd"), "获取的前缀分配到 LAN"),
      ...field("IPv6 源地址路由", inBool(w,"ipv6_srcroute"), "来自本线路前缀的 IPv6 流量从本线路出去（多线必开）"));
    return card(h("span",{}, "WAN · "+(w.name||"(未命名)")+" ", h("span",{class:"tag"}, (PROTOS.find(x=>x[0]===p)||[0,p])[1])),
      [status(w), form(...rows)],
      h("span",{class:"row"}, redial(w), h("button",{class:"btn sm d",onclick:()=>{ if(confirm("删除 WAN "+w.name+"？")){ c.wan.splice(i,1); touch(); draw(); }}},"删除")));
  };
  const add = proto=>{
    // every WAN needs its own metric: take the next free one after the largest
    const n = c.wan.length+1, metric = c.wan.length ? Math.max(...c.wan.map(x=>+x.metric||0))+10 : 0;
    const w = {name:"wan"+n, device:"wan", mac:"", proto, username:"", password_secret:"", mtu:0, metric, peerdns:true, ipv6:false, ipv6_pd:false, ipv6_srcroute:false};
    if (proto==="pppoe") Object.assign(w, {password_secret:"pppoe_password", mtu:1492, ipv6:true, ipv6_pd:true, ipv6_srcroute:true});
    c.wan.push(w); touch(); draw();
  };
  const draw = ()=>box.replaceChildren(dl, ...c.wan.map(wanCard),
    h("div",{class:"row"}, h("button",{class:"btn p",onclick:()=>add("pppoe")},"+ 添加 PPPoE（多拨）"), h("button",{class:"btn",onclick:()=>add("dhcp")},"+ 添加 DHCP / 静态 WAN")));
  draw();
  return box;
});

// ---------- 多线路 ----------
registerPage("network", "multiwan", "多线路", 15, async ()=>{
  const c = S.cfg, m = c.multiwan;
  const stat = h("div"), when = h("span",{class:"mut",style:"font-weight:400;font-size:12px"});
  const draw = async ()=>{
    const r = await api("net.wan"), now = Date.now()/1000;
    stat.replaceChildren(roTable(["WAN","协议","接口","地址","健康","延迟","连续失败","默认路由 metric","路由表 / 标记","权重"], (r.wans||[]).map(w=>[
      h("b",{}, w.name), w.proto, mono(w.dev), w.up ? mono(w.ip) : h("span",{class:"mut"},"未连接"),
      w.health ? h("span",{}, healthTag(w), w.health_since ? h("span",{class:"mut"}, " "+fmtDur(now-w.health_since)) : null) : h("span",{class:"mut"},"未检测"),
      w.rtt_ms!=null ? w.rtt_ms.toFixed(1)+" ms" : "-", w.fails||0,
      w.route_metric!=null ? h("span",{class:w.route_metric>=10000?"err":""}, String(w.route_metric)) : "-",
      mono(w.table+" / "+w.mark), r.mode==="balance" ? String(w.weight??0) : "-"])));
    when.textContent = r.checked ? "上次检测 "+Math.max(0,Math.round(now-r.checked))+" 秒前" : (r.mode ? "检测未运行" : "未启用健康检测");
  };
  try { await draw(); } catch(e){ stat.replaceChildren(h("div",{class:"err"}, e.message)); }
  S.timer = setInterval(()=>draw().catch(()=>{}), 5000);
  // weights: edit a copy so just opening the page never changes the config
  const wt = Object.fromEntries(c.wan.map(w=>[w.name, (m.weights||{})[w.name] ?? (m.weights && Object.keys(m.weights).length ? 0 : 1)]));
  const wtRows = h("div");
  const drawWt = ()=>wtRows.replaceChildren(m.mode!=="balance" ? h("div",{class:"mut"},"仅“负载均衡”模式使用。") :
    form(...c.wan.flatMap(w=>field(w.name, h("input",{type:"number",min:0,max:100,value:wt[w.name],oninput:e=>{ wt[w.name]=e.target.value===""?0:Number(e.target.value); m.weights=Object.assign({},wt); touch(); }}), "0 = 不参与分流，只在其它线路故障时接管"))));
  drawWt();
  return h("div",{},
    card("线路状态", stat, when, true),
    card("健康检测与切换", form(
      ...field("模式", inSel(m,"mode",[["","关闭"],["failover","主备切换（健康检测）"],["balance","负载均衡 + 主备切换"]], ()=>drawWt()),
        "关闭时仍按 metric 主备：PPPoE 掉线自动切到下一条。开启后还会检测“连着但不通”的线路"),
      ...field("检测目标", inList(m,"targets",{placeholder:"1.1.1.1, 8.8.8.8"}), "IPv4 地址，每条线路各自 ping；任一目标回应即算正常（留空默认 1.1.1.1、8.8.8.8）"),
      ...field("检测间隔（秒）", inNum(m,"interval",{min:1,max:300,placeholder:"5",value:m.interval||""})),
      ...field("超时（秒）", inNum(m,"timeout",{min:1,max:10,placeholder:"2",value:m.timeout||""})),
      ...field("连续失败几次判定故障", inNum(m,"fall",{min:1,max:20,placeholder:"3",value:m.fall||""})),
      ...field("连续成功几次判定恢复", inNum(m,"rise",{min:1,max:20,placeholder:"2",value:m.rise||""})))),
    card("负载均衡权重", wtRows),
    card("说明", h("div",{class:"mut"},
      "故障线路的默认路由 metric 加 10000（下一条线路接管），它的策略路由表也暂时不用，按 MAC / 地址指定走它的设备会改走最好的健康线路；恢复后自动切回。",
      h("br"), "负载均衡按连接分配：只分配新的 IPv4 连接，同一个连接始终走同一条线路；策略路由、端口转发的回包优先于均衡。IPv6 不参与均衡（每条线路的前缀不同）。")));
});

// ---------- LAN 与网络 ----------
registerPage("network", "lan", "LAN 与网络", 20, async ()=>{
  const c = S.cfg;
  const [ports, rt] = await Promise.all([portNames(), wanRuntime()]);
  // a WAN lease refused because it overlaps a LAN-side network: offer the free subnet the router found
  const conflicts = (rt.wans||[]).filter(w=>w.conflict);
  const conflictNote = ()=>conflicts.length ? h("div",{class:"notices"}, conflicts.map(w=>{
    const x = w.conflict, tgt = x.network==="lan" ? c.lan : c.networks.find(n=>n.name===x.network);
    const done = tgt && tgt.ipv4===x.suggest;
    return notice("bad", [h("b",{},"WAN "+w.name+"："), "上级网络分配的 ", mono(x.lease), " 和 "+netName(x)+" ", mono(x.net), " 重叠，这个地址没有启用。",
      done ? " 已改为 "+x.suggest+"：点底部“保存并应用”，应用后 WAN 会自动重新获取地址。" : " 改到别的网段并应用后，WAN 会自动重新获取地址。",
      " 静态分配、端口转发里旧网段的地址要一起改（保存时会逐条提示）。"],
      tgt && x.suggest && !done ? h("button",{class:"btn sm p", onclick:()=>{ tgt.ipv4 = x.suggest; touch(); draw(); }}, "改为 "+x.suggest) : null);
  })) : null;
  const wanDevs = new Set(c.wan.filter(w=>!w.vlan).map(w=>w.device));
  const box = h("div");
  // an untagged port belongs to exactly one bridge
  const setUntagged = (port, owner, on)=>{
    c.lan.ports = c.lan.ports.filter(p=>p!==port);
    for (const n of c.networks) n.ports = (n.ports||[]).filter(p=>p!==port);
    if (on){ if (owner) owner.ports = natSort([...(owner.ports||[]), port]); else c.lan.ports = natSort([...c.lan.ports, port]); }
    draw();
  };
  const netCard = (n, i)=>{
    // the pool object joins the config only when edited (opening the page must not change S.cfg)
    const d = n.dhcp || {enabled:false};
    const pool = el=>{ const f=()=>{ n.dhcp=d; touch(); }; el.addEventListener("input",f); el.addEventListener("change",f); return el; };
    return card(h("span",{}, "网络 · "+(n.name||"(未命名)")+" ", h("span",{class:"tag"}, "br-"+(n.name||"?"))), form(
      ...field("名称", inText(n,"name",{maxlength:10}), "小写字母开头，最多 10 个字符；网桥为 br-<名称>"),
      ...field("IPv4 地址 / 掩码", inText(n,"ipv4",{placeholder:"192.168.20.1/24"})),
      ...field("区域", inSel(n,"zone",[["guest","访客：只能上网，不能访问内网和路由器"],["lan","信任：等同 LAN"]])),
      ...field("未打标签端口", checks(ports, p=>(n.ports||[]).includes(p), (p,on)=>setUntagged(p,n,on), p=>wanDevs.has(p)), "从 LAN 中移出，整个口属于本网络"),
      ...field("VLAN ID", inNum(n,"vlan",{min:0,max:4094}), "0 = 不用 VLAN。填了之后在下面选择带标签的端口"),
      ...field("带标签端口 (trunk)", checks(ports, p=>(n.trunk||[]).includes(p), (p,on)=>{ const s=new Set(n.trunk||[]); on?s.add(p):s.delete(p); n.trunk=natSort([...s]); }, p=>wanDevs.has(p)),
        "该口原来的用途不变，额外承载本网络的 802.1Q 标签（<端口>.<VLAN> 加入本网桥），接支持 VLAN 的交换机 / AP"),
      ...field("IPv6 RA / SLAAC", inBool(n,"ipv6_ra")),
      ...field("DHCP 服务", pool(inBool(d,"enabled"))),
      ...field("地址池", pool(h("span",{class:"row"}, inNum(d,"start",{style:"width:90px"}), "—", inNum(d,"end",{style:"width:90px"}))), "主机号，例如 100 — 199"),
      ...field("租期", pool(inText(d,"lease",{placeholder:"12h"})))),
      h("button",{class:"btn sm d",onclick:()=>{ if(confirm("删除网络 "+n.name+"？绑定到它的 WiFi 也要改。")){ c.networks.splice(i,1); touch(); draw(); }}},"删除"));
  };
  const draw = ()=>box.replaceChildren(h("div",{}, conflictNote()),
    card("LAN（主网络）", form(
      ...field("网桥", inText(c.lan,"bridge")),
      ...field("IPv4 地址 / 掩码", inText(c.lan,"ipv4",{placeholder:"192.168.1.1/24"}), "修改后如果浏览器失去连接，超时未确认会自动回滚"),
      ...field("LAN 口", checks(ports, p=>c.lan.ports.includes(p), (p,on)=>setUntagged(p,null,on), p=>wanDevs.has(p)), "WAN 口不能同时做 LAN 口"),
      ...field("IPv6 RA / SLAAC", inBool(c.lan,"ipv6_ra"), "向 LAN 通告 IPv6 前缀"))),
    ...c.networks.map(netCard),
    h("div",{class:"row"}, h("button",{class:"btn p",onclick:()=>{
      const k = c.networks.length;
      c.networks.push({name:k?"net"+(k+1):"guest", ipv4:"192.168."+(20+k*10)+".1/24", zone:"guest", ports:[], vlan:0, trunk:[], ipv6_ra:false, dhcp:{enabled:true, start:100, end:199, lease:"12h"}});
      touch(); draw(); }},"+ 添加网络（访客 / IoT / VLAN）"),
      h("span",{class:"mut"},"WiFi 的 SSID 在“无线设置”里选择加入哪个网络。")));
  draw();
  return box;
});

// ---------- IPv6 ----------
registerPage("network", "ipv6", "IPv6", 60, ()=>{
  const c = S.cfg;
  return h("div",{}, card("LAN", form(...field("IPv6 RA / SLAAC", inBool(c.lan,"ipv6_ra")))),
    card("各 WAN 的 IPv6", roTable(["WAN","IPv6","前缀代理 (PD)","源地址路由"], c.wan.map(w=>[w.name, inBool(w,"ipv6"), inBool(w,"ipv6_pd"), inBool(w,"ipv6_srcroute")])), null, true),
    card("说明", h("div",{class:"mut"},"每条 WAN 用 dhcpcd 请求一个 /64 前缀并加到 LAN；开启源地址路由后，LAN 设备使用哪个前缀的地址就从哪条线路出去，多线 IPv6 互不干扰。多线路健康检测只看 IPv4。")));
});

// ---------- 路由 ----------
const fmtRoute = r=>[mono(r.dst), r.gateway?mono(r.gateway):"", r.dev||"", r.table||"main", r.metric??"", r.protocol||"", (r.flags||[]).join(",")];
const keepRoute = r=>r.table!=="local" && r.type!=="local" && r.type!=="broadcast" && r.type!=="multicast";
const fmtRule = r=>[r.priority, r.src?(r.src+(r.srclen!==undefined?"/"+r.srclen:"")):"all", r.dst?(r.dst+(r.dstlen!==undefined?"/"+r.dstlen:"")):"",
  r.fwmark?(r.fwmark+(r.fwmask?"/"+r.fwmask:"")):"", r.table||r.action||"", r.suppress_prefixlen!==undefined?"suppress /"+r.suppress_prefixlen:""];
const RULE_COLS = ["优先级","来源","目标","fwmark","表 / 动作","其它"];

registerPage("routing", "routes", "静态路由", 10, async ()=>{
  const c = S.cfg;
  let n = {}; try { n = await api("net.routes"); } catch(e){}
  const cols = ["目标","网关","接口","表","跃点","来源","标志"];
  return h("div",{}, tableCard("静态路由", c.static_routes, [{k:"name",l:"名称"},{k:"target",l:"目标网段",ph:"10.0.0.0/8"},{k:"via",l:"网关"},{k:"dev",l:"接口"},{k:"metric",l:"跃点",t:"num",w:"80px"},{k:"table",l:"路由表",t:"num",w:"80px"}],
      {name:"",target:"",via:"",dev:"",metric:0,table:0}, "网关和接口至少填一个；路由表 0 = main。经 PPPoE 接口的路由在线路拨上后自动补上。"),
    tabs([["r4","当前 IPv4 路由", ()=>card("ip -4 route show table all", roTable(cols, (n.route4||[]).filter(keepRoute).map(fmtRoute)), null, true)],
      ["r6","当前 IPv6 路由", ()=>card("ip -6 route show table all", roTable(cols, (n.route6||[]).filter(keepRoute).map(fmtRoute)), null, true)]]));
});

registerPage("routing", "policy", "策略路由", 20, async ()=>{
  const c = S.cfg;
  let n = {}; try { n = await api("net.routes"); } catch(e){}
  return h("div",{}, tableCard("策略路由（指定出口 WAN）", c.policy_routes, [
      {k:"name",l:"名称"},{k:"mac",l:"设备 MAC",ph:"aa:bb:cc:dd:ee:ff"},{k:"src",l:"源地址 / 网段",ph:"192.168.1.66"},{k:"dst",l:"目标地址 / 网段",ph:"1.2.3.0/24"},
      {k:"domains",l:"目标域名",t:"list",ph:"example.com, video.example"},
      {k:"via",l:"出口 WAN",t:"sel",o:()=>c.wan.map(w=>w.name)},{k:"table",l:"路由表",t:"num",w:"80px",ph:"自动"},{k:"mark",l:"标记",w:"90px",ph:"自动"}],
      ()=>({name:"",mac:"",src:"",dst:"",via:(c.wan[1]||c.wan[0]||{}).name||"",table:0,mark:""}),
      "条件同时满足；MAC / 源 / 目标 / 域名至少填一项。没填源 / 目标地址时 IPv4 + IPv6 都生效，填了就只管该地址族。只影响新连接；访问内网、tailscale 和静态路由不受影响。域名含子域名：设备通过路由器 DNS 解析到的地址走该 WAN，连接照常硬件加速（DoH / 自定义 DNS 的设备不生效）。路由表填 0、标记留空 = 自动（200+序号 / 0x200+序号）。"),
    tabs([["p4","IPv4 策略规则", ()=>card("ip -4 rule", roTable(RULE_COLS, (n.rules4||[]).map(fmtRule)), null, true)],
      ["p6","IPv6 策略规则", ()=>card("ip -6 rule", roTable(RULE_COLS, (n.rules6||[]).map(fmtRule)), null, true)]]));
});

registerPage("routing", "mcast", "组播", 40, ()=>{
  const c = S.cfg;
  return card("组播", form(
    ...field("IGMP Snooping", inBool(c.multicast,"igmp_snooping"), "关闭 = 组播泛洪（兼容性最好：AirPlay / 投屏 / mDNS）"),
    ...field("IGMP 代理", inBool(c.multicast,"igmp_proxy"), "把某条 WAN 的组播（IPTV 等）转发到 LAN"),
    ...field("上游 WAN", inSel(c.multicast,"upstream", [["","（无）"], ...c.wan.map(w=>w.name)]))));
});
})();
