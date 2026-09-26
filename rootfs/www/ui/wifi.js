// mini-router web UI — wifi module pages. Uses the helpers in ui/core.js; see docs/MODULES.md.
"use strict";
(()=>{
const CH2 = ["auto",...Array.from({length:13},(_,i)=>String(i+1))];
const CH5 = ["auto",...[36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165].map(String)];
const COUNTRIES = ["PA","US","CN","TH","JP","SG","HK","TW","KR","GB","DE","FR","AU","CA","MY","VN","ID","PH","IN","AE"];
const MAX_SSIDS = 4;
const ENC = [["sae-mixed","WPA2/WPA3 混合"],["sae","WPA3-SAE"],["psk2","WPA2-PSK"],["none","无加密（开放）"]];
const PMF = [["","默认（可选）"],["optional","可选"],["required","强制"],["disabled","关闭（兼容老设备）"]];
const STATE_TXT = {ENABLED:"工作中", DFS:"雷达检测 (DFS)", ACS:"自动选频中", HT_SCAN:"40MHz 共存扫描", COUNTRY_UPDATE:"等待国家码", DISABLED:"已停用", NO_IR:"禁止发射", UNINITIALIZED:"未初始化"};
const bandName = b => b==="2g" ? "2.4 GHz" : b==="5g" ? "5 GHz" : b==="6g" ? "6 GHz" : (b||"");
const apIfs = r => (r.ssids||[]).map((_,i)=> i ? r.phy+"-ap0-"+i : r.phy+"-ap0");
const netOpts = ()=>[["","lan（主网络）"], ...(S.cfg.networks||[]).map(n=>[n.name, n.name+(n.zone==="lan"?"（内网）":"（访客：仅上网）")])];
const guestNet = ()=>((S.cfg.networks||[]).find(n=>(n.zone||"guest")==="guest")||{}).name;
// a secret name no SSID uses yet: a reused name would silently give the new SSID another SSID's password
const freeKey = r=>{ const used = new Set(S.cfg.wifi.radios.flatMap(x=>(x.ssids||[]).map(s=>s.key_secret)));
  let n = (r.ssids||[]).length; while (used.has("wifi_key_"+r.phy+"_"+n)) n++; return "wifi_key_"+r.phy+"_"+n; };
const sigTag = dbm => h("span",{class:"tag "+(!dbm?"":dbm>=-60?"ok":dbm>=-72?"warn":"bad")}, dbm ? dbm+" dBm" : "-");
const stateTag = (st, cac)=> st ? h("span",{class:"tag "+(st==="ENABLED"?"ok":st==="DFS"||st==="ACS"||st==="HT_SCAN"?"warn":"bad")},
  (STATE_TXT[st]||st)+(st==="DFS"&&cac?" · 剩 "+cac+" 秒":"")) : h("span",{class:"tag bad"},"未运行");
// an optional sub-object (wifi.steering) that only enters the config once edited
const lazy = (parent, key, init)=>{ const o = parent[key] || init(); return {o, attach:()=>{ if(!parent[key]) parent[key]=o; touch(); }}; };
const onEdit = (el, fn)=>{ el.addEventListener("input", fn); el.addEventListener("change", fn); return el; };
// SSIDs steering can move clients between: same name, encryption, password name and network on 2.4 and 5 GHz
const steerPairs = w=>{
  const r2 = (w.radios||[]).find(r=>r.band==="2g"), r5 = (w.radios||[]).find(r=>r.band==="5g");
  if (!r2 || !r5) return [];
  const net = s=>s.network||"lan", out = [];
  (r2.ssids||[]).forEach((a,i)=>(r5.ssids||[]).forEach((b,j)=>{
    if (a.ssid && a.ssid===b.ssid && a.encryption===b.encryption && (a.key_secret||"")===(b.key_secret||"") && net(a)===net(b))
      out.push({ssid:a.ssid, from:apIfs(r2)[i], to:apIfs(r5)[j]}); }));
  return out;
};

addCSS(`
.wifi-ta{min-height:64px;resize:vertical}
.wifi-sub{font-weight:400;color:var(--mut);font-size:12px}
.wifi-cur td{background:rgba(47,111,237,.07)}
.wifi-own td{color:var(--mut)}
.wifi-occ{display:grid;grid-template-columns:repeat(auto-fill,minmax(46px,1fr));gap:6px;align-items:end;padding:12px 16px}
.wifi-occ .c{display:flex;flex-direction:column;align-items:center;font-size:11px;color:var(--mut)}
.wifi-occ .b{width:18px;background:var(--acc);border-radius:3px 3px 0 0;opacity:.8}
.wifi-occ .c.me .b{background:var(--ok)}
.wifi-occ .c.me{color:var(--ok);font-weight:600}
.wifi-warn{padding:10px 16px;color:var(--warn);font-size:12px}
.wifi-acts{padding:0 16px 12px;font-size:12px;display:flex;flex-direction:column;gap:3px}
`);

// textarea bound to an array of MAC addresses (one per line; commas/spaces also split)
function inMacs(obj, key){
  return h("textarea",{class:"wifi-ta", rows:3, placeholder:"aa:bb:cc:dd:ee:ff", spellcheck:false,
    oninput:e=>{ obj[key]=e.target.value.split(/[\s,;]+/).map(x=>x.trim().toLowerCase()).filter(Boolean); touch(); }},
    (obj[key]||[]).join("\n"));
}

// ---------- 无线设置 ----------
registerPage("wireless", "wifi", "无线设置", 10, async ()=>{
  const c = S.cfg; c.wifi ||= {}; c.wifi.radios ||= [];
  let live = {}; // ifname -> live BSS state (clients, radio state)
  try { for (const w of await api("wifi.status")) live[w.ifname]=w; } catch(e){}
  const dl = h("datalist",{id:"wifi-cc"}, COUNTRIES.map(x=>h("option",{value:x})));
  const glob = card("全局", form(...field("国家码", inText(c.wifi,"country",{list:"wifi-cc",maxlength:2,style:"max-width:100px",placeholder:"PA"}), "两位大写字母")));
  if (!c.wifi.radios.length) return h("div",{}, dl, glob, card("射频", h("div",{class:"mut"},"router.yaml 中没有配置射频。")));
  return h("div",{}, dl, glob, tuneCard(c.wifi), tabs(c.wifi.radios.map(r=>[r.phy, bandName(r.band)+" · "+r.phy, ()=>radioTab(r, live)])));
});

// 自动调优（#41）：频段引导 + 射频自愈，都由每分钟一次的 `mr wifi tick`（crond）完成，没有常驻进程
function tuneCard(w){
  const st = lazy(w, "steering", ()=>({enabled:false}));
  const pairs = h("div",{class:"hint"});
  const showPairs = ()=>{
    const p = steerPairs(w);
    pairs.replaceChildren(p.length ? tr("可引导："+p.map(x=>x.ssid+"（"+x.from+" → "+x.to+"）").join("，"))
      : h("span",{style:"color:var(--warn)"}, "没有两个频段同名、同加密、同密码、同网络的 SSID：开启后校验会失败。把 2.4G 和 5G 的 SSID 改成同一个名字即可。"));
  };
  showPairs();
  return card("自动调优", [
    onEdit(form(
      ...field("频段引导 (802.11v)", inBool(st.o,"enabled",()=>{ st.attach(); showPairs(); }), "每分钟检查一次：2.4G 上信号好、支持 802.11v 的终端，建议它换到同名的 5G（终端可以拒绝，不会被踢下线；同一台设备 30 分钟内只问一次，一天最多 3 次）"),
      ...field("", pairs),
      ...field("引导门限 (dBm)", inNum(st.o,"min_signal_2g",{min:-90,max:-30,placeholder:"-60"}), "2.4G 信号不低于这个值才建议换 5G；0 = -60"),
      ...field("不引导的设备", inMacs(st.o,"exclude"), "每行一个 MAC，例如只连 2.4G 更稳的 IoT")), ()=>st.attach()),
    form(...field("射频自愈", inBool(w,"self_heal"), "有终端在线、但发送计数 10 分钟不动时：先触发驱动的固件恢复（SER，约几秒，终端一般不掉线），仍不行再重启 hostapd；不会重启路由器。每一步都记在“体检与事件”里")),
    h("div",{class:"mut",style:"font-size:12px;margin-top:8px"}, "运行情况见“无线 › 射频健康”。组播转单播在每个 SSID 的设置里。")]);
}

function radioTab(r, live){
  r.ssids ||= [];
  const box = h("div");
  const draw = ()=>{
    const w = live[r.phy+"-ap0"];
    const radio = card(h("span",{}, "射频 · "+bandName(r.band)+" ", h("span",{class:"wifi-sub mono"}, r.phy+"-ap0")), form(
      ...field("信道", inSel(r,"channel", r.band==="2g"?CH2:CH5)),
      ...field("自动选频范围", inText(r,"channels",{placeholder:r.band==="2g"?"1-11":"36-48 149-165"}), "仅信道为 auto 时使用"),
      ...field("频宽", inSel(r,"htmode", r.band==="2g" ? [["HE20","20 MHz"],["HE40","40 MHz"]] : [["HE20","20 MHz"],["HE40","40 MHz"],["HE80","80 MHz"],["HE160","160 MHz"]])),
      ...field("发射功率 (dBm)", inNum(r,"txpower",{min:0,max:40}), "0 = 驱动默认"),
      ...field("Beacon 间隔 (TU)", inNum(r,"beacon_int",{min:10,max:10000,placeholder:"100"}), "默认 100（约 102 ms）"),
      ...field("DTIM 周期", inNum(r,"dtim_period",{min:1,max:255,placeholder:"2"}), "默认 2；越大终端越省电，组播/广播延迟越高"),
      ...(r.band==="2g" ? field("允许 802.11b 速率", inBool(r,"legacy_rates"), "只有很老的设备需要；开启会拖慢整个 2.4G 频段") : [])),
      w ? h("span",{class:"row"}, stateTag(w.state, w.cac_left), w.channel ? h("span",{class:"tag"}, "信道 "+w.channel+" · "+w.htmode) : null) : null);
    const full = r.ssids.length >= MAX_SSIDS, g = guestNet();
    const add = guest=>{
      r.ssids.push(guest
        ? {ssid:((r.ssids[0]||{}).ssid||"WiFi")+"-Guest", key_secret:"wifi_guest_key", encryption:"sae-mixed", hidden:false, isolate:true, network:g}
        : {ssid:"", key_secret:freeKey(r), encryption:"sae-mixed", hidden:false});
      touch(); draw();
    };
    box.replaceChildren(radio, ...r.ssids.map((s,i)=>ssidCard(r, s, i, live, draw)),
      h("div",{class:"row",style:"margin-bottom:18px"},
        h("button",{class:"btn p", disabled:full, onclick:()=>add(false)}, "+ 添加 SSID"),
        h("button",{class:"btn", disabled:full||!g, title:g?"":"先在“网络”里添加一个访客区域的网络", onclick:()=>add(true)}, "+ 添加访客 SSID"),
        h("span",{class:"mut",style:"font-size:12px"}, "每个频段最多 "+MAX_SSIDS+" 个 SSID；增删 SSID 应用时该频段 WiFi 会重启几秒")));
  };
  draw();
  return box;
}

function ssidCard(r, s, i, live, redraw){
  const ifn = apIfs(r)[i], w = live[ifn];
  const body = h("div");
  const drawBody = ()=>{
    const enc = s.encryption || "none";
    body.replaceChildren(form(
      ...field("SSID 名称", inText(s,"ssid",{maxlength:32})),
      ...field("接入网络", inSel(s,"network", netOpts())),
      ...field("加密", inSel(s,"encryption", ENC, v=>{ if(v==="none") delete s.pmf; else if(!s.key_secret) s.key_secret=freeKey(r); if(v==="sae" || (v==="sae-mixed" && s.pmf==="disabled")) delete s.pmf; drawBody(); })),
      ...(enc!=="none" ? [
        ...field("密码引用名", inText(s,"key_secret",{placeholder:"wifi_key"}), "密码在 secrets.yaml 里的名字；多个 SSID 用同一个名字即共用一个密码"),
        ...field("密码", inSecret(s,"key_secret"), "8–63 位可打印 ASCII"),
        ...(enc==="sae" ? field("管理帧保护 (802.11w)", h("span",{class:"mut"},"强制（WPA3 必需）"))
                        : field("管理帧保护 (802.11w)", inSel(s,"pmf", enc==="sae-mixed" ? PMF.filter(p=>p[0]!=="disabled") : PMF),
                            enc==="psk2" ? "老旧 IoT 设备连不上时可选“关闭”" : null)),
      ] : []),
      ...field("隐藏 SSID", inBool(s,"hidden")),
      ...field("客户端隔离", inBool(s,"isolate"), "终端之间互不可见（也看不到其他开启隔离的 SSID 的终端），仍可上网"),
      ...field("组播转单播", inBool(s,"multicast_to_unicast"), "mDNS / AirPlay / 投屏 / IPTV 等组播逐个终端单播发送：用终端自己的速率、有确认重传，更稳更快；终端很多且组播流量大时多占空口"),
      ...field("最大终端数", inNum(s,"max_clients",{min:0,max:2007,placeholder:"0"}), "0 = 不限制"),
      ...field("MAC 过滤", inSel(s,"macfilter", [["","关闭"],["allow","白名单：只允许列表内设备"],["deny","黑名单：拒绝列表内设备"]], ()=>drawBody())),
      ...(s.macfilter ? field("MAC 列表", inMacs(s,"maclist"), "每行一个；手机要关掉“私有/随机 MAC 地址”才能匹配") : [])));
  };
  drawBody();
  const title = h("span",{}, "SSID "+(i+1)+" ", h("span",{class:"wifi-sub mono"}, ifn),
    s.network ? h("span",{class:"tag warn",style:"margin-left:6px"}, s.network) : null,
    w ? h("span",{class:"tag",style:"margin-left:6px"}, w.clients+" 个终端") : null);
  const del = h("button",{class:"btn sm d", disabled:r.ssids.length<=1, onclick:()=>{
    if (!confirm("删除 SSID “"+(s.ssid||"(未命名)")+"”？")) return;
    r.ssids.splice(i,1); touch(); redraw(); }}, "删除");
  return card(title, body, del);
}

// ---------- 无线终端 ----------
// find the SSID config behind an AP netdev
function ssidOf(ifname){
  for (const r of (S.cfg&&S.cfg.wifi&&S.cfg.wifi.radios)||[]){ const k = apIfs(r).indexOf(ifname); if (k>=0) return r.ssids[k]; }
  return null;
}
function blacklist(x, name){
  const s = ssidOf(x.ifname);
  if (!s) return toast("找不到该终端所在的 SSID 配置");
  if (!confirm("把 "+name+" 加入 “"+s.ssid+"” 的黑名单？\n现在先踢下线；点底部“保存并应用”后永久生效（该频段 WiFi 会重启几秒）。")) return;
  s.maclist ||= [];
  if (s.macfilter==="allow") s.maclist = s.maclist.filter(m=>m!==x.mac);
  else { s.macfilter = "deny"; if (!s.maclist.includes(x.mac)) s.maclist.push(x.mac); }
  touch();
  api("wifi.kick",{mac:x.mac, ifname:x.ifname}).then(()=>toast("已踢下线，黑名单待应用")).catch(e=>toast(e.message,4000));
}

registerPage("wireless", "wifi-clients", "无线终端", 20, async ()=>{
  const wrap = h("div");
  let leases = {}, leasesAt = 0; // names / IPs from the DHCP leases in the status JSON (refreshed every 30 s)
  const air = {}; // mac -> {t, us}: airtime share between two refreshes
  const draw = async ()=>{
    const [cl, st] = await Promise.all([api("wifi.stations"), Date.now()-leasesAt>30000 ? api("status").catch(()=>null) : null]);
    if (st){ leases = {}; for (const l of st.leases||[]) leases[(l.mac||"").toLowerCase()] = l; leasesAt = Date.now(); }
    const now = Date.now();
    const airPct = x=>{
      if (x.airtime_tx_us===undefined && x.airtime_rx_us===undefined) return "-";
      const us = (x.airtime_tx_us||0)+(x.airtime_rx_us||0), p = air[x.mac]; air[x.mac] = {t:now, us};
      if (!p || now<=p.t || us<p.us) return "…";
      const v = (us-p.us)/((now-p.t)*1000)*100;
      return h("span",{title:"最近一次刷新间隔内该终端占用的空口时间（收 + 发）"}, v<0.1 ? "<0.1%" : v.toFixed(v<10?1:0)+"%");
    };
    const list = (cl.stations||[]).slice().sort((a,b)=>(a.ssid||"").localeCompare(b.ssid||"") || (b.signal_dbm||-999)-(a.signal_dbm||-999));
    const per = {}; for (const x of list){ const k = (x.ssid||x.ifname)+" · "+bandName(x.band); per[k]=(per[k]||0)+1; }
    const rows = list.map(x=>{
      const l = leases[x.mac]||{}, name = l.name && l.name!=="*" ? l.name : "";
      return [
        h("span",{}, h("b",{}, name||"（未知）"), h("br"), h("span",{class:"mono mut"}, l.ip||"-")),
        h("span",{class:"mono"}, x.mac),
        h("span",{}, x.ssid||"-", h("br"), h("span",{class:"mut",style:"font-size:12px"}, bandName(x.band)+(x.network&&x.network!=="lan"?" · "+x.network:""))),
        sigTag(x.signal_dbm),
        h("span",{class:"mono",title:"↓ "+(x.tx_rate||"")+"\n↑ "+(x.rx_rate||"")}, "↓ "+Math.round(x.tx_mbps||0)+" / ↑ "+Math.round(x.rx_mbps||0)+" Mbps"),
        h("span",{class:"mono"}, "↓ "+fmtBytes(x.tx_bytes)+" / ↑ "+fmtBytes(x.rx_bytes)),
        airPct(x),
        fmtDur(x.connected),
        h("span",{class:"row",style:"flex-wrap:nowrap"},
          confirmBtn("踢下线", "断开 "+(name||x.mac)+"？设备一般会自动重连；要阻止它请用“拉黑”。", async()=>{ await api("wifi.kick",{mac:x.mac, ifname:x.ifname}); toast("已断开"); draw().catch(()=>{}); }),
          h("button",{class:"btn sm",onclick:()=>blacklist(x, name||x.mac)},"拉黑")),
      ];
    });
    wrap.replaceChildren(card(h("span",{}, "无线终端（"+list.length+"）"),
      [h("div",{class:"row",style:"padding:10px 16px"}, Object.keys(per).length ? Object.entries(per).map(([k,n])=>h("span",{class:"tag"}, k+"："+n)) : h("span",{class:"mut"},"暂无终端")),
       roTable(["设备 / IP","MAC","SSID","信号","协商速率","流量","空口","在线","操作"], rows)],
      h("span",{class:"mut",style:"font-size:12px;font-weight:400"}, "每 5 秒刷新 · ↓ 为终端下载方向"), true));
  };
  await draw();
  S.timer = setInterval(()=>draw().catch(()=>{}), 5000);
  return wrap;
});

// ---------- 信道分析 ----------
registerPage("wireless", "wifi-channels", "信道分析", 30, async ()=>{
  const wrap = h("div");
  const prev = {}, scans = {}, scanning = {};
  const draw = async ()=>{
    const sv = await api("wifi.survey");
    wrap.replaceChildren(...(sv.radios||[]).map(r=>radioCard(r)),
      card("说明", h("div",{class:"mut",style:"font-size:12px"},
        "繁忙率 = 信道被占用（本机收发 + 周边干扰）的时间比例，按驱动的累计计数计算；当前信道的“实时”值是最近 5 秒的变化。",
        " 周边扫描只显示数据，不会改动你的信道设置。")));
  };
  const radioCard = r=>{
    const cur = (r.channels||[]).find(c=>c.in_use);
    let live = null;
    if (cur){ const p = prev[r.phy]; if (p && cur.active_ms>p.active_ms) live = (cur.busy_ms-p.busy_ms)/(cur.active_ms-p.active_ms)*100; prev[r.phy] = {active_ms:cur.active_ms, busy_ms:cur.busy_ms}; }
    const pct = c=>c.active_ms ? c.busy_ms/c.active_ms*100 : 0;
    const bar = v=>h("div",{class:"bar",style:"margin:0;min-width:60px"}, h("i",{style:"width:"+Math.min(100,v).toFixed(0)+"%;background:"+(v>60?"var(--bad)":v>30?"var(--warn)":"var(--ok)")}));
    const rows = (r.channels||[]).map(c=>h("tr",{class:c.in_use?"wifi-cur":""},
      h("td",{}, h("b",{}, c.channel), c.in_use ? h("span",{class:"tag ok",style:"margin-left:6px"},"当前") : null),
      h("td",{class:"mono"}, c.freq+" MHz"), h("td",{}, c.noise ? c.noise+" dBm" : "-"),
      h("td",{}, h("div",{class:"row",style:"flex-wrap:nowrap"}, bar(pct(c)), pct(c).toFixed(0)+"%")),
      h("td",{}, c.active_ms ? (c.rx_ms/c.active_ms*100).toFixed(0)+"%" : "-"),
      h("td",{}, c.active_ms ? (c.tx_ms/c.active_ms*100).toFixed(0)+"%" : "-")));
    const survey = h("div",{class:"tw"}, h("table",{}, h("thead",{}, h("tr",{}, ["信道","频率","噪声","繁忙率","接收","发送"].map(x=>h("th",{},x)))),
      h("tbody",{}, rows.length ? rows : h("tr",{}, h("td",{colspan:6,class:"mut"}, r.error ? "读取失败："+r.error : "（暂无数据；扫描一次后会有更多信道）")))));
    const btn = h("button",{class:"btn sm p", disabled:!!scanning[r.phy], onclick:async()=>{
      if (!confirm("扫描时 "+bandName(r.band)+" 会短暂离开当前信道，已连接的终端会卡顿几秒。继续？")) return;
      scanning[r.phy] = true; btn.disabled = true; btn.textContent = tr("扫描中…");
      try { scans[r.phy] = await api("wifi.scan",{phy:r.phy}); } catch(e){ toast("扫描失败："+e.message, 5000); }
      scanning[r.phy] = false; draw().catch(()=>{}); }}, scanning[r.phy] ? "扫描中…" : "扫描周边网络");
    const kv = h("dl",{class:"kv",style:"padding:12px 16px;margin:0"},
      h("dt",{},"状态"), h("dd",{}, stateTag(r.state, r.cac_left)),
      h("dt",{},"当前信道"), h("dd",{}, r.channel ? r.channel+" · "+r.width+" MHz" : "-"),
      h("dt",{},"配置"), h("dd",{class:"mono"}, r.config||"-"),
      h("dt",{},"实时繁忙率"), h("dd",{}, live===null ? "…" : live.toFixed(0)+"%"));
    return card(h("span",{}, bandName(r.band)+" ", h("span",{class:"wifi-sub mono"}, r.ifname)),
      [kv, survey, h("div",{class:"wifi-warn"}, "注意：扫描周边网络会让该频段的终端短暂断流（约 2–8 秒）。"), scans[r.phy] ? scanView(scans[r.phy], r) : null], btn, true);
  };
  await draw();
  S.timer = setInterval(()=>draw().catch(()=>{}), 5000);
  return wrap;
});

// ---------- 射频健康（#41）：温度 / 降频、空口公平、固件、发送计数、自愈、频段引导 ----------
const STAGE_TXT = {ser:["已触发固件恢复 (SER)","warn"], restart:["已重启 hostapd","warn"], failed:["自愈已放弃：请重启路由器","bad"]};
const ACT_TXT = {ser:"固件恢复 (SER)", restart:"重启 hostapd", failed:"放弃（不会自动重启路由器）", recovered:"发送恢复正常"};
const stamp = t=>new Date(t*1000).toLocaleString([], {month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit", hour12:false});
const tag = (txt, cls)=>h("span",{class:"tag "+(cls||""), style:"white-space:nowrap"}, txt);

registerPage("wireless", "wifi-health", "射频健康", 40, async ()=>{
  const wrap = h("div"), prev = {};
  let leases = {};
  try { for (const l of (await api("status")).leases||[]) leases[(l.mac||"").toLowerCase()] = l; } catch(e){}
  const who = mac=>{ const l = leases[mac]||{}; return l.name && l.name!=="*" ? l.name : mac; };
  const draw = async ()=>{
    const j = await api("wifi.health");
    wrap.replaceChildren(...(j.radios||[]).map(r=>healthCard(r, j, prev)), steerCard(j.steering||{}, who),
      card("说明", h("div",{class:"mut",style:"font-size:12px"},
        "发送 = 硬件统计的、终端已确认收到的帧（含 WED 硬件转发的流量）。开启“射频自愈”后，有终端在线而它 10 分钟不动，就先触发驱动自带的固件恢复（SER），",
        "10 分钟后仍不动再重启 hostapd，再不行只记事件、不会重启路由器。空口公平 (ATF) 是固件的 VoW 调度，WED 硬件转发的流量也受它管；驱动默认开启。")));
  };
  await draw();
  S.timer = setInterval(()=>draw().catch(()=>{}), 5000);
  return wrap;
});

function healthCard(r, j, prev){
  const p = prev[r.phy], t = j.time||0;
  let rate = null;
  if (p && r.has_tx && p.has && t>p.t) rate = ((r.tx_acked - p.tx + 4294967296) % 4294967296)/(t-p.t);
  prev[r.phy] = {t, tx:r.tx_acked, has:r.has_tx};
  const heal = !j.self_heal ? h("span",{class:"mut"},"未开启（无线设置 › 自动调优）")
    : r.heal_stage ? tag(STAGE_TXT[r.heal_stage][0], STAGE_TXT[r.heal_stage][1])
    : r.stalled_s>=60 ? tag("发送停滞 "+fmtDur(r.stalled_s), "warn") : tag("正常","ok");
  const kv = h("dl",{class:"kv",style:"padding:12px 16px;margin:0"},
    h("dt",{},"状态"), h("dd",{}, stateTag(r.state), " ", r.stations+" 个终端"),
    h("dt",{},"温度"), h("dd",{}, r.temp_c ? r.temp_c.toFixed(0)+" °C" : "-", r.crit_c ? h("span",{class:"mut"}," （"+r.crit_c.toFixed(0)+" °C 起降频）") : null),
    h("dt",{},"发射占空比"), h("dd",{}, !r.tx_duty ? "-" : r.tx_duty>=100 ? tag("100%（未降频）","ok") : tag(r.tx_duty+"%（过热降频）","warn")),
    h("dt",{},"发送（已确认帧）"), h("dd",{class:"mono"}, !r.has_tx ? "-" : rate===null ? "…" : Math.round(rate).toLocaleString()+" 帧/秒"),
    h("dt",{},"空口公平 (ATF)"), h("dd",{}, r.atf==="on" ? tag("硬件 VoW：开","ok") : r.atf==="off" ? tag("硬件 VoW：关","warn")
      : h("span",{class:"mut"},"此内核的 mt76 不支持（WED 转发的流量不受空口公平调度）")),
    h("dt",{},"固件 CPU"), h("dd",{}, r.fw_busy>=0 ? r.fw_busy+"%" : h("span",{class:"mut"},"未上报（驱动只在固件调试打开时提供）")),
    h("dt",{},"固件重启"), h("dd",{}, r.fw_resets<0 ? "-" : r.fw_resets ? tag(r.fw_resets+" 次（驱动加载以来）","warn") : "0"),
    h("dt",{},"射频自愈"), h("dd",{}, heal));
  const acts = (r.heal_actions||[]).slice(-5).reverse();
  return card(h("span",{}, bandName(r.band)+" ", h("span",{class:"wifi-sub mono"}, r.phy+(r.kphy&&r.kphy!==r.phy?" · 内核 "+r.kphy:""))),
    [kv, acts.length ? h("div",{class:"wifi-acts"}, h("div",{class:"mut"},"自愈记录"),
      acts.map(a=>h("div",{}, h("span",{class:"mono mut"}, stamp(a.t)+" "), ACT_TXT[a.action]||a.action, a.detail ? h("span",{class:"mut"}," · "+a.detail) : null))) : null],
    null, true);
}

function steerCard(s, who){
  const c = s.counts||{};
  const res = x=>x.result==="accepted" ? tag("接受","ok") : x.result==="no answer" ? tag("无应答","") : /^declined/.test(x.result||"") ? tag("拒绝"+(x.result.match(/\d+/)?" ("+x.result.match(/\d+/)[0]+")":""),"warn") : tag(x.result||"-","bad");
  const rows = (s.recent||[]).slice().reverse().map(x=>[
    h("span",{class:"mono mut"}, stamp(x.t)),
    h("span",{title:x.ssid+"："+x.from+" → "+x.to}, who(x.mac), " ", sigTag(x.signal)),
    h("span",{class:"row",style:"gap:4px"}, res(x), x.moved ? tag("已到 5G","ok") : null)]);
  const head = h("dl",{class:"kv",style:"padding:12px 16px;margin:0"},
    h("dt",{},"状态"), h("dd",{}, s.enabled ? tag("已开启","ok") : h("span",{class:"mut"},"未开启（无线设置 › 自动调优）")),
    h("dt",{},"门限"), h("dd",{}, "2.4G 信号 ≥ "+(s.min_signal_2g||-60)+" dBm"+(s.excluded ? " · 排除 "+s.excluded+" 台" : "")),
    h("dt",{},"同名 SSID"), h("dd",{}, (s.pairs||[]).length ? s.pairs.map(p=>h("div",{}, p.ssid+" ", h("span",{class:"mono mut"}, p.from+" → "+p.to))) : "-"),
    h("dt",{},"统计"), h("dd",{}, (c.sent||0)+" 次建议 · "+(c.accepted||0)+" 接受 · "+(c.rejected||0)+" 拒绝 · "+(c.noreply||0)+" 无应答 · "+(c.moved||0)+" 已换到 5G",
      s.since ? h("span",{class:"mut"}," （"+stamp(s.since)+" 起）") : null));
  const devs = Object.entries(s.devices||{}).sort((a,b)=>b[1].last-a[1].last).map(([m,d])=>[who(m), d.accepted||0, d.rejected||0, d.noreply||0, d.moved||0]);
  return card("频段引导 (802.11v)", [head, roTable(["时间","设备 / 2.4G 信号","结果"], rows),
    devs.length ? roTable(["设备","接受","拒绝","无应答","已换到 5G"], devs) : null], null, true);
}

function scanView(sc, r){
  const bss = sc.bss||[];
  const byCh = {};
  for (const b of bss){ const k=b.channel; byCh[k] ||= {n:0, best:-200}; byCh[k].n++; byCh[k].best=Math.max(byCh[k].best, b.signal); }
  const chans = Object.keys(byCh).map(Number).sort((a,b)=>a-b);
  if (r.channel && !byCh[r.channel]) { chans.push(r.channel); chans.sort((a,b)=>a-b); }
  const max = Math.max(1, ...chans.map(c=>(byCh[c]||{n:0}).n));
  const occ = h("div",{class:"wifi-occ"}, chans.map(c=>{ const o = byCh[c]||{n:0};
    return h("div",{class:"c"+(c===r.channel?" me":""), title:o.n+" 个 AP"+(o.n?"，最强 "+o.best.toFixed(0)+" dBm":"")},
      h("span",{}, o.n), h("div",{class:"b",style:"height:"+Math.max(2, o.n/max*60).toFixed(0)+"px"}), h("span",{}, c)); }));
  const rows = bss.map(b=>h("tr",{class:b.own?"wifi-own":""},
    h("td",{}, b.ssid ? b.ssid : h("span",{class:"mut"},"（隐藏）"), b.own ? h("span",{class:"tag",style:"margin-left:6px"},"本机") : null),
    h("td",{class:"mono"}, b.bssid), h("td",{}, b.channel), h("td",{}, b.width+" MHz"),
    h("td",{}, sigTag(Math.round(b.signal))), h("td",{}, b.security), h("td",{}, b.standard==="legacy"?"a/b/g":"11"+b.standard),
    h("td",{}, b.stations>=0 ? b.stations+" 台 / "+b.util+"%" : "-")));
  return h("div",{},
    h("div",{class:"mut",style:"padding:10px 16px 0;font-size:12px"}, "周边网络 "+bss.length+" 个 · 扫描于 "+new Date((sc.time||0)*1000).toLocaleTimeString()+" · 柱高 = 每个信道上的 AP 数（绿色为本机信道）"),
    occ,
    h("div",{class:"tw"}, h("table",{}, h("thead",{}, h("tr",{}, ["SSID","BSSID","信道","频宽","信号","加密","标准","终端 / 利用率"].map(x=>h("th",{},x)))),
      h("tbody",{}, rows.length ? rows : h("tr",{}, h("td",{colspan:8,class:"mut"},"（没有发现其他网络）"))))));
}
})();
