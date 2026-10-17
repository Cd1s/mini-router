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
// wanRefs: the settings that name WAN `name` and would fail validation without it, as [{what, drop}];
// drop() removes the reference. v6: only those that need its IPv6 + prefix (nat6 policies), for turning
// ipv6 / ipv6_pd off. A firewall rule limited to this WAN alone is removed, not widened to every WAN.
function wanRefs(c, name, v6){
  const out = [], ref = (what, drop)=>out.push({what, drop});
  const dropFrom = (list, x)=>{ const i = list.indexOf(x); if (i>=0) list.splice(i,1); };
  for (const p of c.policy_routes||[]) if (p.via===name && (!v6 || p.nat6))
    ref("策略路由 "+p.name, ()=>dropFrom(c.policy_routes, p));
  if (v6) return out;
  const m = c.multiwan||{};
  if (m.weights && name in m.weights) ref("多线路权重", ()=>{ delete m.weights[name]; });
  if ((m.dial_order||[]).includes(name)) ref("拨号顺序", ()=>{
    m.dial_order = m.dial_order.filter(x=>x!==name);
    if (m.dial_order.length<2){ m.dial_order = []; delete m.dial_wait; delete m.dial_restore; }
  });
  const mc = c.multicast||{};
  if (mc.igmp_proxy && mc.upstream===name) ref("组播代理（上游）", ()=>{ mc.igmp_proxy = false; mc.upstream = ""; });
  const f = c.firewall||{};
  for (const [k, label] of [["forwards","端口转发"],["open","开放端口"],["ipv6_allow","IPv6 入站"]])
    for (const r of f[k]||[]) if ((r.wan||[]).includes(name)) ref(label+" "+r.name, ()=>{
      r.wan = r.wan.filter(x=>x!==name);
      if (!r.wan.length) dropFrom(f[k], r);
    });
  const recs = ((c.services||{}).ddns||{}).records||[];
  for (const r of recs.slice()) if (r.ipv4===name || r.ipv6===name) ref("DDNS "+r.name, ()=>{
    if (r.ipv4===name) r.ipv4 = "off";
    if (r.ipv6===name) r.ipv6 = "off";
    if ((r.ipv4||"off")==="off" && (r.ipv6||"off")==="off") dropFrom(recs, r);
  });
  for (const s of c.schedules||[]) if (s.action==="reconnect" && s.target===name)
    ref("定时任务 "+s.name, ()=>dropFrom(c.schedules, s));
  if (m.mode && c.wan.length - 1 < 2)
    ref("关闭多线路", ()=>{ m.mode = ""; delete m.weights; });
  return out;
}
// confirmRefs: asks before `msg`, listing what goes with it; false = cancelled.
function confirmRefs(msg, refs){
  if (!confirm(msg + (refs.length ? "\n\n引用它的这些设置会一起删除：\n· "+refs.map(r=>r.what).join("\n· ") : ""))) return false;
  refs.forEach(r=>r.drop());
  return true;
}
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

// Turning IPv6 or delegated prefixes off must remove policy routes that depend on them before apply.
// The same callback is used by the WAN card and the separate IPv6 page so both entry points behave alike.
const v6off = (c, w, key, redraw)=>on=>{
  if (on) return;
  const refs = wanRefs(c, w.name, true);
  if (refs.length && !confirmRefs("关闭 "+(key==="ipv6"?"IPv6":"IPv6 前缀")+" ("+w.name+")?", refs)) {
    w[key] = true;
    touch();
    redraw();
    return;
  }
  touch();
  redraw();
};

// The DNS module's controlled list editor is backed by dns.files. Policy routes use the same
// directory and file contract so a domain list can be selected and edited without shell access.
const netDNSFileSelect = (obj, key, files, onchange)=>{
  const current = obj[key]||"";
  const opts = [["","（不使用文件）"], ...(files||[]).filter(f=>f.name.endsWith(".domains")).map(f=>[f.path,f.name])];
  if (current && !opts.some(x=>x[0]===current)) opts.splice(1,0,[current,current.split("/").pop()+"（当前）"]);
  return inSel(obj,key,opts,onchange);
};
const netManagedDNSFile = p=>{
  const s=String(p||""), prefix="/etc/mini-router/dns/", name=s.startsWith(prefix)?s.slice(prefix.length):"";
  return name && !name.includes("/") && /^[A-Za-z0-9_-]{1,64}\.domains$/.test(name) ? name : "";
};
const netListFileEditor = (ed,file,after)=>api("dns.files",{file}).then(j=>{
  const ta=h("textarea",{rows:16,spellcheck:false},j.content||"");
  ed.replaceChildren(card("列表文件 · "+file,[h("div",{class:"mut",style:"margin-bottom:8px"},(j.path||file)+" — 每行一个域名，# 开头为注释"),ta,
    h("div",{class:"row",style:"margin-top:10px"},h("button",{class:"btn p",onclick:async()=>{
      try { await api("dns.files",{file,content:ta.value,save:true}); toast("已保存，点击底部“保存并应用”生效"); S.orig=""; touch(); after&&await after(); }
      catch(e) { toast("保存失败："+e.message,5000); }
    }},"保存列表"),h("button",{class:"btn",onclick:()=>ed.replaceChildren()},"关闭"))]));
}).catch(e=>toast(e.message,4000));

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
    when.textContent = tr("每 3 秒刷新");
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
    if (p!=="pppoe") {
      const m = c.multiwan||{};
      if ((m.dial_order||[]).includes(w.name)) {
        m.dial_order = m.dial_order.filter(x=>x!==w.name);
        if (m.dial_order.length < 2) {
          delete m.dial_order;
          delete m.dial_wait;
          delete m.dial_restore;
        }
      }
      delete w.modem;
    } else if (!w.password_secret) {
      w.password_secret = "pppoe_password";
    }
    if (p==="pppoe" && !w.mtu) w.mtu = 1492;
    if (p!=="pppoe" && w.mtu===1492) w.mtu = 0;
    draw();
  };
  const status = w=>{
    const r = live[w.name];
    if (!r) return h("div",{class:"net-rt"}, "（尚未应用）");
    const now = Date.now()/1000;
    return h("div",{class:"net-rt row"}, h("span",{class:"dot "+(r.up?"ok":"bad")}),
      r.up ? ["已连接 ", mono(r.ip), r.gateway?[" · 网关 ", mono(r.gateway)]:null, r.overlap?[" · 上游/LAN 同网段 ", mono(r.overlap)]:null, r.since?" · "+fmtDur(now-r.since):null, (r.dns||[]).length?" · DNS "+r.dns.join(", "):null] : "未连接",
      " · 接口 ", mono(r.dev), healthTag(r));
  };
  const redial = w=>{
    if (!svcOf(w) || !live[w.name]) return null;
    return h("button",{class:"btn sm",onclick:async()=>{
      if (!confirm((w.proto==="pppoe"?"重新拨号 ":"重新获取地址 ")+w.name+"？这条线路会短暂断开。")) return;
      try { await api("net.redial",{wan:w.name}); toast("正在重连 "+w.name, 3000); } catch(e){ toast(e.message, 4000); } }}, w.proto==="pppoe"?"重新拨号":"重新获取");
  };
  const wanCard = (w, i)=>{
    const p = w.proto;
    const detect = h("button",{class:"btn sm",onclick:async()=>{
      try {
        const d = await api("net.wan_detect",{port:w.device,timeout:8});
        const apply = ()=>{ if(!d.recommendation||d.recommendation==="unknown") return toast("未得到可靠的上网方式建议",4000); w.proto=d.recommendation||w.proto; if(w.proto==="pppoe"){w.password_secret||="pppoe_password";w.mtu=1492;} if(w.proto==="static"&&d.dhcp&&d.dhcp.offer){const bits=(d.dhcp.mask||"255.255.255.0").split(".").reduce((n,x)=>{let v=+x;while(v){n+=v&1;v>>=1;}return n;},0);w.ipv4=d.dhcp.address+"/"+bits;w.gateway=d.dhcp.gateway;w.dns=d.dhcp.dns||[];} touch(); m.remove(); draw(); };
        const m = modal("检测上网方式", [h("p",{},d.recommendation==="pppoe"?"检测到 PPPoE PADO":d.recommendation==="dhcp"?"检测到 DHCP OFFER":"未发现 DHCP / PPPoE，建议静态地址"), d.dhcp&&d.dhcp.offer?h("pre",{},JSON.stringify(d.dhcp,null,2)):null, d.lan_conflict?h("div",{class:"tag warn"},"与当前 LAN 冲突，建议 "+d.suggested_lan):null], [h("button",{class:"btn",onclick:()=>m.remove()},"关闭"),h("button",{class:"btn p",onclick:apply},"套用建议")]);
      } catch(e) { toast("检测失败："+e.message,4000); }
    }},"检测上网方式");
    const rows = [
      ...field("名称", inText(w,"name"), p==="pppoe" ? "PPPoE 接口为 pppoe-<名称>，最多 9 个字符" : "小写字母开头"),
      ...field("协议", inSel(w,"proto",PROTOS, v=>setProto(w,v))),
      ...field("物理接口", inText(w,"device",{placeholder:"wan", list:"net-portlist"}), "同一个网口可以跑多条 PPPoE（多拨）"),
      ...field("VLAN", inNum(w,"vlan",{min:0,max:4094}), "0 = 不打标签；运营商要求时填（例如 PPPoE 走 VLAN 500）"),
    ];
    if (p==="pppoe") {
      rows.push(
        ...field("PPPoE 账号", inText(w,"username")),
        ...field("密码引用名", inText(w,"password_secret",{placeholder:"pppoe_password"}), "密码保存在 secrets.yaml，多条 WAN 可共用一个"),
        ...field("PPPoE 密码", inSecret(w,"password_secret")));
      const modem = w.modem||{};
      const modemToggle = h("label",{class:"sw"}, h("input",{type:"checkbox",checked:!!w.modem?.address,onchange:e=>{
        if (e.target.checked) { w.modem ||= {}; }
        else delete w.modem;
        touch(); draw();
      }}), h("span"));
      const modemInput = h("input",{type:"text",value:modem.address||"",placeholder:"192.168.1.1",disabled:!w.modem?.address,oninput:e=>{
        w.modem ||= {};
        w.modem.address = e.target.value;
        touch();
      }});
      rows.push(...field("光猫管理页", h("span",{class:"row"},modemToggle,modemInput), "启用后，局域网设备可访问桥接光猫的管理页（例如 192.168.1.1）；地址必须是上级私网 IPv4。"));
    }
    if (p==="static") rows.push(
      ...field("IPv4 地址 / 掩码", inText(w,"ipv4",{placeholder:"203.0.113.10/24"})),
      ...field("网关", inText(w,"gateway",{placeholder:"203.0.113.1"})),
      ...field("DNS 服务器", inList(w,"dns",{placeholder:"1.1.1.1, 8.8.8.8"}), "最多 3 个，交给 dnsmasq 作为上游"));
    rows.push(
      ...field("克隆 MAC", inText(w,"mac",{placeholder:"留空使用默认"}), "作用于物理接口；同一口上后面的 PPPoE 用它自己的 MAC（macvlan）"),
      ...field("MTU", inNum(w,"mtu"), p==="pppoe" ? "PPPoE 一般 1492" : "0 = 不修改"),
      ...field("路由跃点 (metric)", inNum(w,"metric",{min:0,max:9999}), "越小越优先，每条 WAN 各不相同；主线路 0，备用线路更大（多线路按它主备切换）"));
    if (p!=="static") rows.push(...field("使用运营商 DNS", inBool(w,"peerdns")));
    rows.push(
      ...field("IPv6", inBool(w,"ipv6",v6off(c,w,"ipv6",draw)), "dhcpcd 获取 IPv6（RA / DHCPv6）"),
      ...field("请求 IPv6 前缀 (PD)", inBool(w,"ipv6_pd",v6off(c,w,"ipv6_pd",draw)), "获取的前缀分配到 LAN"),
      ...field("IPv6 源地址路由", inBool(w,"ipv6_srcroute"), "来自本线路前缀的 IPv6 流量从本线路出去（多线必开）"));
    const secondary = p==="pppoe" && c.wan.slice(0,i).some(x=>x.proto==="pppoe" && x.device===w.device && (Number(x.vlan)||0)===(Number(w.vlan)||0));
    const genMac = secondary ? h("button",{class:"btn sm",onclick:async()=>{
      if (w.mac && !confirm("这条 WAN 已有克隆 MAC（"+w.mac+"）。覆盖后应用会让该线路重拨，运营商可能按 MAC 认证，确定继续？")) return;
      try {
        const j = await api("net.wan_mac",{wan:w.name,device:w.device,vlan:Number(w.vlan)||0});
        w.mac = j.mac;
        touch();
        draw();
        toast("已生成多拨 MAC："+j.mac,3000);
      } catch(e) { toast("生成多拨 MAC 失败："+e.message,5000); }
    }},"生成多拨 MAC") : null;
    return card(h("span",{}, "WAN · "+(w.name||"(未命名)")+" ", h("span",{class:"tag"}, (PROTOS.find(x=>x[0]===p)||[0,p])[1])),
      [status(w), form(...rows)],
      h("span",{class:"row"}, detect, redial(w), genMac, h("button",{class:"btn sm d",onclick:()=>{ if(confirmRefs("删除 WAN "+w.name+"？", wanRefs(c, w.name))){ c.wan.splice(i,1); touch(); draw(); }}},"删除")));
  };
  const add = proto=>{
    // every WAN needs its own metric: take the next free one after the largest
    const n = c.wan.length+1, metric = c.wan.length ? Math.max(...c.wan.map(x=>+x.metric||0))+10 : 0;
    const w = {name:"wan"+n, device:"wan", mac:"", proto, username:"", password_secret:"", mtu:0, metric, peerdns:true, ipv6:false, ipv6_pd:false, ipv6_srcroute:false};
    if (proto==="pppoe") Object.assign(w, {password_secret:"pppoe_password", mtu:1492, ipv6:true, ipv6_pd:true, ipv6_srcroute:true});
    c.wan.push(w); touch(); draw();
    if (proto==="pppoe" && c.wan.filter(x=>x.proto==="pppoe" && x.device===w.device && (Number(x.vlan)||0)===(Number(w.vlan)||0)).length>1)
      api("net.wan_mac",{wan:w.name,device:w.device,vlan:Number(w.vlan)||0}).then(j=>{ w.mac=j.mac; touch(); draw(); }).catch(e=>toast("自动生成多拨 MAC 失败："+e.message,5000));
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
      mono(w.table+" / "+w.mark), r.mode==="balance" ? String(w.weight??0) : "-"])),
      r.dial_order ? h("div",{class:"mut",style:"margin-top:8px"}, "拨号顺序", " "+r.dial_order.join(" → ")+": ",
        r.dial_order_ok ? "正常" : h("span",{class:"err"}, "乱序", " ("+(r.dial_late||[]).join(", ")+")"),
        r.dial_restore_at ? " → "+r.dial_restore : "") : "");
    when.textContent = tr(r.checked ? "上次检测 "+Math.max(0,Math.round(now-r.checked))+" 秒前" : (r.mode ? "检测未运行" : "未启用健康检测"));
  };
  try { await draw(); } catch(e){ stat.replaceChildren(h("div",{class:"err"}, e.message)); }
  S.timer = setInterval(()=>draw().catch(()=>{}), 5000);
  // weights: edit a copy so just opening the page never changes the config
  const wt = Object.fromEntries(c.wan.map(w=>[w.name, (m.weights||{})[w.name] ?? (m.weights && Object.keys(m.weights).length ? 0 : 1)]));
  const wtRows = h("div");
  const drawWt = ()=>wtRows.replaceChildren(m.mode!=="balance" ? h("div",{class:"mut"},"仅“负载均衡”模式使用。") :
    form(...c.wan.flatMap(w=>field(w.name, h("input",{type:"number",min:0,max:100,value:wt[w.name],oninput:e=>{ wt[w.name]=e.target.value===""?0:Number(e.target.value); m.weights=Object.assign({},wt); touch(); }}), "0 = 不参与分流，只在其它线路故障时接管"))));
  drawWt();
  const restore = {mode:m.dial_restore==="now"?"now":m.dial_restore && m.dial_restore!=="off"?"time":"off", time:m.dial_restore && /^\d{2}:\d{2}$/.test(m.dial_restore)?m.dial_restore:"04:30"};
  const restoreControl = h("span",{class:"row"});
  const applyRestore = ()=>{ m.dial_restore = restore.mode==="time" ? restore.time : restore.mode; touch(); };
  const drawRestore = ()=>restoreControl.replaceChildren(
    inSel(restore,"mode",[["off","关闭自动恢复"],["now","线路上线后立即恢复"],["time","每天定时恢复"]],()=>{ applyRestore(); drawRestore(); }),
    h("input",{type:"time",value:restore.time,disabled:restore.mode!=="time",title:"本地时间 HH:MM",oninput:e=>{ restore.time=e.target.value; if(restore.mode==="time") applyRestore(); }})
  );
  drawRestore();
  const dialNow = h("button",{class:"btn sm p",title:"按已应用的拨号顺序，只重拨乱序或晚到的线路",disabled:(m.dial_order||[]).length<2,onclick:async()=>{
    try {
      const j = await api("net.dial_restore",{}), redialled=j.redialled||[], failed=j.failed||[];
      if (redialled.length || failed.length) {
        const parts=[];
        if (redialled.length) parts.push("已按顺序重拨："+redialled.join("、"));
        if (failed.length) parts.push("失败："+failed.join("、"));
        toast(parts.join("；"),5000);
      }
      else if (j.reason==="order_ok") toast("拨号顺序正常，无需重拨",4000);
      else if (j.reason==="already_running") toast("已有一次顺序恢复正在进行",4000);
      else toast("没有可执行的顺序恢复",4000);
    } catch(e) { toast("重拨失败："+e.message,5000); }
  }},"立即按顺序重拨");
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
    card("拨号顺序", form(
      ...field("PPPoE 顺序", inList(m,"dial_order",{placeholder:"wan, wan2, wan3"}), "同一物理口的多条 PPPoE 按从前到后拨号；至少两条 PPPoE 才能启用。"),
      ...field("等待前一条（秒）", inNum(m,"dial_wait",{min:1,max:120,placeholder:"30",value:m.dial_wait||""}), "后一条最多等待前面的线路上线；留空使用默认 30 秒。"),
      ...field("顺序乱了时", restoreControl, "只重拨乱序 / 晚到的线路；可选关闭、线路上线后立即恢复或每天定时恢复。")), dialNow),
    card("负载均衡权重", wtRows),
    card("说明", h("div",{class:"mut"},
      "故障线路的默认路由 metric 加 10000（下一条线路接管），它的策略路由表也暂时不用，按 MAC / 地址指定走它的设备会改走最好的健康线路；恢复后自动切回。",
      h("br"), "负载均衡按连接分配：只分配新的 IPv4 连接，同一个连接始终走同一条线路；策略路由、端口转发的回包优先于均衡。IPv6 不参与均衡（每条线路的前缀不同）。")));
});

// ---------- LAN 与网络 ----------
registerPage("network", "lan", "LAN 与网络", 20, async ()=>{
  const c = S.cfg;
  const ports = await portNames();
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
  // 工作模式（mode, #24 / #26）：主路由 / 旁路由 / 纯 AP
  const routes = h("div",{class:"mut"});
  const modeCard = ()=>{
    const mode = c.mode || "";
    const bp = c.bypass || {}; const attach = ()=>{ if (!c.bypass) c.bypass = bp; touch(); };
    const body = [...field("工作模式", inSel(c,"mode",[["","主路由（默认）"],["bypass","旁路由：挂在主路由下，负责 DNS 和代理"],["ap","纯 AP / 交换机：只桥接，不路由"]], ()=>draw()),
      mode ? "旁路由和纯 AP 没有 WAN、端口转发、多线路、策略路由和附加网络；保存时会列出需要先删掉的项目" : null)];
    if (mode) body.push(...field("主路由地址", inText(c.lan,"gateway",{placeholder:"192.168.1.1"}), "本机的默认网关和 DNS 上游。本机地址用固定地址，不要落在主路由的地址池里"));
    if (mode==="bypass") {
      body.push(...field("客户端", onEdit(inSel(bp,"clients",[["","只管代理（推荐）"],["all","全部设备"],["selected","指定设备"]], ()=>draw()), attach),
        !bp.clients ? "主路由仍是所有设备的网关和 DHCP；在主路由上把 DNS 指向本机，并添加下面的静态路由。只有被代理的连接经过本机，其余流量和主路由的硬件加速不受影响" :
        bp.clients==="all" ? "本机发 DHCP（先关掉主路由的 DHCP），所有设备以本机为网关和 DNS。本机挂了全家断网" :
        "本机发 DHCP（先关掉主路由的 DHCP）；只有下面这些设备以本机为网关和 DNS，其余设备仍走主路由"));
      if (bp.clients==="selected") body.push(...field("设备 MAC", onEdit(inList(bp,"macs",{placeholder:"aa:bb:cc:dd:ee:ff, …"}), attach)));
      if (bp.clients) body.push(...field("NAT", h("label",{class:"sw"}, h("input",{type:"checkbox", checked: bp.nat!==false, onchange:e=>{ bp.nat = e.target.checked; attach(); }}), h("span")),
        "转发的流量伪装成本机地址（默认开）。关掉后主路由会把回包直接发给设备，连接会被丢弃"));
      if (!bp.clients) { body.push(...field("主路由静态路由", routes, "代理网段（fake-ip 和规则里的 IP 段）都指向本机。应用后生成；命令行：mr proxy routes"));
        api("proxy.routes").then(j=>routes.replaceChildren(...(j.routes.length ? j.routes.map(r=>h("div",{class:"mono"},r)) : [h("span",{},"（保存并应用、开启代理后显示）")]))).catch(e=>routes.textContent=e.message); }
    }
    return card("工作模式", form(...body.filter(Boolean)));
  };
  const onEdit = (el, fn)=>{ el.addEventListener("input", fn); el.addEventListener("change", fn); return el; };
  const draw = ()=>box.replaceChildren(
    modeCard(),
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
  const c = S.cfg, box = h("div");
  const draw = ()=>box.replaceChildren(
    card("LAN", form(...field("IPv6 RA / SLAAC", inBool(c.lan,"ipv6_ra")))),
    card("各 WAN 的 IPv6", roTable(["WAN","IPv6","前缀代理 (PD)","源地址路由"], c.wan.map(w=>[
      w.name,
      inBool(w,"ipv6",v6off(c,w,"ipv6",draw)),
      inBool(w,"ipv6_pd",v6off(c,w,"ipv6_pd",draw)),
      inBool(w,"ipv6_srcroute")
    ])), null, true),
    card("说明", h("div",{class:"mut"},"每条 WAN 用 dhcpcd 请求一个 /64 前缀并加到 LAN；开启源地址路由后，LAN 设备使用哪个前缀的地址就从哪条线路出去，多线 IPv6 互不干扰。多线路健康检测只看 IPv4。"))
  );
  draw();
  return box;
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
  let n = {}, files = [];
  try { n = await api("net.routes"); } catch(e){}
  try { files = (await api("dns.files",{})).files||[]; } catch(e){}
  const fileEd = h("div"), policyBody = h("div");
  const policyNote = "条件同时满足；MAC（或 网络 › 设备 里的设备名 / group:分组）/ 源 / 目标 / 域名至少填一项。没填源 / 目标地址时 IPv4 + IPv6 都生效，填了就只管该地址族。只影响新连接；多条同时命中时，排在前面的那条生效；访问内网、tailscale 和静态路由不受影响。域名含子域名：设备通过路由器 DNS 解析到的地址走该 WAN，连接照常硬件加速（DoH / 自定义 DNS 的设备不生效）。“断网”= 该 WAN 断线或健康检查失败时这些流量直接丢弃，绝不从其他 WAN 出去（该 WAN 没有 IPv6 时，这些设备也就没有 IPv6 外网）。路由表填 0、标记留空 = 自动（200+序号 / 0x200+序号）。";
  const blankPolicy = ()=>({name:"",mac:"",device:"",src:"",dst:"",domains:[],domains_file:"",via:(c.wan[1]||c.wan[0]||{}).name||"",fallback:"",nat6:false,table:0,mark:""});
  function drawPolicy(){
    const cols=["名称","设备 MAC","设备 / 分组","源地址 / 网段","目标地址 / 网段","目标域名","域名列表文件","出口 WAN","断线时","IPv6 全走","表","标记","操作"];
    const rows=c.policy_routes.map((p,i)=>h("tr",{},
      h("td",{},inText(p,"name")), h("td",{},inText(p,"mac",{placeholder:"aa:bb:cc:dd:ee:ff"})),
      h("td",{},inText(p,"device",{placeholder:"desktop / group:kids"})), h("td",{},inText(p,"src",{placeholder:"192.168.1.66"})),
      h("td",{},inText(p,"dst",{placeholder:"1.2.3.0/24"})), h("td",{},inList(p,"domains",{placeholder:"example.com, video.example"})),
      h("td",{},h("span",{class:"row"},netDNSFileSelect(p,"domains_file",files,()=>{ touch(); drawPolicy(); }),h("button",{class:"btn sm",disabled:!netManagedDNSFile(p.domains_file),title:!netManagedDNSFile(p.domains_file)?"只有受控目录中的文件可编辑":"",onclick:()=>netListFileEditor(fileEd,netManagedDNSFile(p.domains_file),async()=>{ files=(await api("dns.files",{})).files||[]; drawPolicy(); })},"编辑列表"))),
      h("td",{},inSel(p,"via",c.wan.map(w=>w.name))), h("td",{},inSel(p,"fallback",[["","换线"],["drop","断网"]])),
      h("td",{},inBool(p,"nat6")), h("td",{},inNum(p,"table",{placeholder:"自动"})), h("td",{},inText(p,"mark",{placeholder:"自动"})),
      h("td",{style:"width:1%;white-space:nowrap"},h("button",{class:"btn sm",title:"上移",disabled:i===0,onclick:()=>{[c.policy_routes[i-1],c.policy_routes[i]]=[c.policy_routes[i],c.policy_routes[i-1]];touch();drawPolicy();}},"↑")," ",h("button",{class:"btn sm d",onclick:()=>{c.policy_routes.splice(i,1);touch();drawPolicy();}},"删除"))));
    policyBody.replaceChildren(h("div",{class:"tw"},h("table",{},h("thead",{},h("tr",{},cols.map(x=>h("th",{},x)))),h("tbody",{},rows.length?rows:h("tr",{},h("td",{colspan:cols.length,class:"mut"},"（空）"))))));
  }
  const addPolicy=h("button",{class:"btn sm p",onclick:()=>{c.policy_routes.push(blankPolicy());touch();drawPolicy();}},"+ 添加");
  drawPolicy();
  return h("div",{}, card("策略路由（指定出口 WAN）", [h("div",{class:"mut",style:"padding:10px 16px 0"},policyNote),policyBody], addPolicy, true), fileEd,
    Object.keys(n.learned||{}).length ? card("域名策略已学到的地址", roTable(["策略","IPv4","IPv6"],
      Object.entries(n.learned).map(([k,v])=>[k, String(v.v4??"-"), String(v.v6??"-")])), null, true) : null,
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
