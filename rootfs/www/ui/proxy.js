// mini-router web UI — proxy module pages (selective transparent proxy: sing-box fake-ip + tproxy).
// Uses the helpers in ui/core.js; see docs/MODULES.md and docs/modules/proxy.md.
"use strict";
(()=>{
addCSS(`
.proxy-ta{min-height:88px;resize:vertical}
.proxy-d{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;white-space:nowrap}
.proxy-d.ok{color:var(--ok)}.proxy-d.warn{color:var(--warn)}.proxy-d.bad{color:var(--bad)}
.proxy-mem{display:flex;flex-wrap:wrap;gap:2px 10px}
.proxy-mem label{white-space:nowrap}
.proxy-rule .form{grid-template-columns:120px minmax(0,1fr)}
.proxy-sum{font-size:12px;color:var(--mut);white-space:nowrap}
tr.proxy-cur td{background:rgba(47,111,237,.07)}
.proxy-sec{grid-column:1/-1;font-weight:600;font-size:12px;color:var(--mut);border-bottom:1px solid var(--line);padding-top:6px}
.proxy-errs{margin:8px 16px;padding-left:18px;font-size:12px}
@media (max-width:820px){.proxy-rule .form{grid-template-columns:1fr}}
`);
const METHODS = [
  ["2022-blake3-aes-128-gcm","2022-blake3-aes-128-gcm（推荐）"], ["2022-blake3-aes-256-gcm","2022-blake3-aes-256-gcm"],
  ["2022-blake3-chacha20-poly1305","2022-blake3-chacha20-poly1305"], ["aes-128-gcm","aes-128-gcm（推荐，旧协议）"],
  ["aes-192-gcm","aes-192-gcm"], ["aes-256-gcm","aes-256-gcm"], ["chacha20-ietf-poly1305","chacha20-ietf-poly1305"],
  ["xchacha20-ietf-poly1305","xchacha20-ietf-poly1305"]];
const PORTS = [["tproxy_port","透明代理端口",7893],["dns_port","sing-box DNS 端口",1053],["lan_dns_port","代理 DNS 端口 (dnsmasq)",1054],["api_port","sing-box API 端口",9090]];

// Node types and the router.yaml keys each one uses (mirror of proxyTypes in mr/mod_proxy_node.go;
// the backend validates, this only decides which fields to show and what to drop on a type switch).
const TYPES = [["","Shadowsocks"],["vless","VLESS"],["vmess","VMess"],["trojan","Trojan"],["hysteria2","Hysteria2"],["tuic","TUIC v5"],
  ["anytls","AnyTLS"],["socks","SOCKS5"],["http","HTTP / HTTPS"],["custom","自定义 JSON"]];
const K_TLS = " tls sni alpn insecure", K_TR = " transport path host service_name early_data", K_RE = " reality_public_key reality_short_id";
const KEYS = {
  "": "server port method password_secret tcp_only",
  vless: "server port uuid_secret flow packet_encoding tcp_only fingerprint"+K_TLS+K_RE+K_TR,
  vmess: "server port uuid_secret security alter_id packet_encoding tcp_only fingerprint"+K_TLS+K_TR,
  trojan: "server port password_secret tcp_only fingerprint"+K_TLS+K_RE+K_TR,
  hysteria2: "server port password_secret up_mbps down_mbps obfs obfs_password_secret hop_ports tcp_only"+K_TLS,
  tuic: "server port uuid_secret password_secret congestion_control udp_relay_mode tcp_only"+K_TLS,
  anytls: "server port password_secret fingerprint"+K_TLS+K_RE,
  socks: "server port username password_secret tcp_only",
  http: "server port username password_secret fingerprint"+K_TLS,
  custom: "json_secret",
};
const TLS_ALWAYS = new Set(["hysteria2","tuic","anytls"]);   // QUIC / TLS-only protocols
const SECRET_SUFFIX = {password_secret:"password", uuid_secret:"uuid", obfs_password_secret:"obfs", json_secret:"json"};
const DEF_PORT = {"":8388, socks:1080, http:8080};
const FPS = ["chrome","firefox","edge","safari","ios","android","360","qq","random","randomized"];
const typeOf = n=>n.type==="shadowsocks" ? "" : (n.type||"");
const has = (n,k)=>(KEYS[typeOf(n)]||"").split(" ").includes(k);

// S.cfg.proxy with its lists present. Filling in missing empty lists is not a user change, so the
// "unsaved changes" bar stays off if the config was clean before.
function P(){
  const clean = S.orig === JSON.stringify(S.cfg);
  const p = S.cfg.proxy ||= {};
  for (const k of ["nodes","groups","rules","bypass"]) p[k] ||= [];
  if (clean) S.orig = JSON.stringify(S.cfg);
  return p;
}
const outbounds = p=>[...p.groups.map(g=>[g.name, g.name+"（组）"]), ...p.nodes.map(n=>[n.name, n.name])].filter(o=>o[0]);
const delayEl = d=>{
  if (d===undefined || d===null) return h("span",{class:"proxy-d mut"},"-");
  if (d==="…") return h("span",{class:"proxy-d mut"},"测试中…");
  if (d<=0) return h("span",{class:"proxy-d bad"},"超时");
  return h("span",{class:"proxy-d "+(d<200?"ok":d<500?"warn":"bad")}, d+" ms");
};
async function status(){ try { return await api("proxy.status"); } catch(e){ return {error:e.message}; } }
// secrets_set from the proxy API: the core config API only reports WAN / WiFi secrets
function learnSecrets(st){ Object.assign(S.secretsSet, st.secrets_set||{}); }
// a text area bound to a list of strings (one per line); an empty list removes the key
function lines(obj, key, ph){
  return h("textarea",{class:"proxy-ta", rows:4, placeholder:ph, spellcheck:false, oninput:e=>{
    const v = e.target.value.split("\n").map(s=>s.trim()).filter(Boolean);
    if (v.length) obj[key] = v; else delete obj[key];
    touch(); }}, (obj[key]||[]).join("\n"));
}
function uniqueName(base, taken){ let i=1; while (taken.has(base+i)) i++; return base+i; }
// "HK-01" taken → "HK-01-2"
function freeName(base, taken){ if (!taken.has(base)) return base; let i=2; while (taken.has(base+"-"+i)) i++; return base+"-"+i; }

// optional fields: an empty value removes the key, so router.yaml stays clean
function optText(obj, key, attrs){
  return h("input",Object.assign({type:"text", value:obj[key]??"", spellcheck:false, oninput:e=>{ const v=e.target.value.trim(); if (v) obj[key]=v; else delete obj[key]; touch(); }}, attrs||{}));
}
function optNum(obj, key, attrs){
  return h("input",Object.assign({type:"number", min:0, value:obj[key]||"", oninput:e=>{ const v=e.target.value; if (v===""||Number(v)===0) delete obj[key]; else obj[key]=Number(v); touch(); }}, attrs||{}));
}
function optList(obj, key, attrs){ // comma separated
  return h("input",Object.assign({type:"text", value:(obj[key]||[]).join(", "), spellcheck:false, oninput:e=>{
    const v = e.target.value.split(/[\s,]+/).filter(Boolean); if (v.length) obj[key]=v; else delete obj[key]; touch(); }}, attrs||{}));
}
function optSel(obj, key, opts, after){ return inSel(obj, key, opts, v=>{ if (v==="") delete obj[key]; touch(); after&&after(v); }); }
function optBool(obj, key, after){ return inBool(obj, key, v=>{ if (!v) delete obj[key]; touch(); after&&after(v); }); }

// secrets.yaml names for node credentials: proxy_<node>_<field> (same scheme as mr/mod_proxy_node.go)
function secretName(node, suffix, taken){
  const base = (node||"node").toLowerCase().replace(/[^a-z0-9_-]/g,"_");
  const max = 40 - "proxy__".length - suffix.length;
  for (let i=1;;i++){
    const tail = i>1 ? String(i) : "";
    const name = "proxy_"+base.slice(0, max-tail.length)+tail+"_"+suffix;
    if (!taken.has(name)){ taken.add(name); return name; }
  }
}
// secret names used by every node / subscription except `except`
function usedSecrets(p, except){
  const s = new Set();
  for (const n of p.nodes) if (n!==except) for (const k of Object.keys(SECRET_SUFFIX)) if (n[k]) s.add(n[k]);
  for (const x of p.subscriptions||[]) if (x.url_secret) s.add(x.url_secret);
  return s;
}
// a credential of a node: the value goes to S.secrets under the node's secret name, which is created
// on first input (and dropped again if it was never saved)
function secretIn(p, n, key, textarea){
  const name = n[key];
  const attrs = {placeholder: name && S.secretsSet[name] ? "已设置（留空不变）" : "未设置", spellcheck:false, autocomplete:"new-password",
    oninput:e=>{
      const v = e.target.value;
      if (!n[key]){ if (!v) return; n[key] = secretName(n.name, SECRET_SUFFIX[key], usedSecrets(p, n)); }
      if (v) S.secrets[n[key]] = v; else { delete S.secrets[n[key]]; if (!S.secretsSet[n[key]]) delete n[key]; }
      touch(); }};
  const v = name && S.secrets[name] || "";
  return textarea ? h("textarea",Object.assign({class:"proxy-ta", rows:5}, attrs), v) : h("input",Object.assign({type:"password", value:v}, attrs));
}
// short description of a node for lists ("vless · reality · vision"), like the backend's proxyNodeSummary
function summary(n){
  const t = typeOf(n), parts = [t||"ss"];
  if (t==="") parts.push(n.method||"");
  if (t==="vmess" && n.security && n.security!=="auto") parts.push(n.security);
  if (t==="hysteria2"){ if (n.obfs) parts.push(n.obfs); if (n.hop_ports) parts.push("hop "+n.hop_ports); }
  if (t==="tuic" && n.congestion_control) parts.push(n.congestion_control);
  if (n.transport) parts.push(n.transport);
  if (n.reality_public_key) parts.push("reality"); else if (n.tls && !TLS_ALWAYS.has(t)) parts.push("tls");
  if (n.flow) parts.push("vision");
  if (n.insecure) parts.push("insecure");
  if (n.tcp_only) parts.push("仅 TCP");
  return parts.filter(Boolean).join(" · ");
}
// switching the node type keeps name, server, port and the credentials the new type also uses
function setType(p, n, t){
  const keep = new Set(("name "+KEYS[t]).split(" "));
  for (const k of Object.keys(n)) if (!keep.has(k)) delete n[k];
  if (t) n.type = t; else delete n.type;
  if (t!=="custom"){
    n.server ??= ""; n.port ||= DEF_PORT[t] || 443;
    if (t==="") n.method ||= "2022-blake3-aes-128-gcm";
    if (t==="trojan" || t==="vless") n.tls = true;
  }
  touch();
}

// ---------------- 代理节点 ----------------
registerPage("proxy", "proxy-nodes", "代理节点", 10, async ()=>{
  const p = P();
  const st = await status(); learnSecrets(st);
  const delays = {};
  for (const [k,v] of Object.entries(st.proxies||{})) if (v.delay) delays[k] = v.delay;
  let editing = null;          // the node shown in the editor
  let showImport = false;

  const rename = (from, to)=>{
    if (!from || from===to) return;
    for (const g of p.groups) g.nodes = (g.nodes||[]).map(x=>x===from?to:x);
    for (const r of p.rules) if (r.outbound===from) r.outbound = to;
  };
  const test = async name=>{
    const names = name ? [name] : p.nodes.map(n=>n.name);
    for (const n of names) delays[n] = "…";
    drawNodes();
    try { const j = await api("proxy.delay", name?{name}:{}); Object.assign(delays, j.results||{}); }
    catch(e){ for (const n of names) delays[n] = undefined; toast("测速失败："+e.message, 4000); }
    drawNodes();
  };

  // node list
  const nodeBody = h("tbody");
  const drawNodes = ()=>{
    nodeBody.replaceChildren();
    if (!p.nodes.length) nodeBody.append(h("tr",{}, h("td",{colspan:6,class:"mut"},"（还没有节点：点“+ 添加节点”，或“导入链接 / 订阅”）")));
    p.nodes.forEach((n,i)=>{
      const t = typeOf(n);
      nodeBody.append(h("tr",{class:n===editing?"proxy-cur":""},
        h("td",{}, h("b",{}, n.name||"(未命名)")),
        h("td",{style:"white-space:nowrap"}, (TYPES.find(x=>x[0]===t)||[t,t])[1]),
        h("td",{class:"mono"}, t==="custom" ? h("span",{class:"mut"},"JSON") : (n.server||"?")+":"+(n.port||"?")),
        h("td",{}, h("span",{class:"proxy-sum"}, t==="custom" ? "sing-box outbound" : summary(n))),
        h("td",{}, delayEl(delays[n.name])),
        h("td",{style:"width:1%;white-space:nowrap"},
          h("button",{class:"btn sm",disabled:!st.running,onclick:()=>test(n.name)},"测速"), " ",
          h("button",{class:"btn sm"+(n===editing?" p":""),onclick:()=>{ editing = n===editing ? null : n; drawNodes(); drawEditor(); }},"编辑"), " ",
          h("button",{class:"btn sm",title:"上移",disabled:i===0,onclick:()=>{ [p.nodes[i-1],p.nodes[i]]=[p.nodes[i],p.nodes[i-1]]; touch(); drawNodes(); }},"↑"), " ",
          h("button",{class:"btn sm d",onclick:()=>{ if (!confirm("删除节点 "+(n.name||"")+"？")) return; p.nodes.splice(i,1);
            if (editing===n) editing = null; touch(); drawNodes(); drawEditor(); drawGroups(); }},"删除"))));
    });
  };
  const addNode = ()=>{
    const names = new Set([...p.nodes, ...p.groups].map(x=>x.name));
    const n = {name: uniqueName("node", names)};
    setType(p, n, "");
    p.nodes.push(n);
    editing = n;
    touch(); drawNodes(); drawEditor(); drawGroups();
    editorBox.scrollIntoView({behavior:"smooth", block:"start"});
  };

  // node editor: only the fields of the node's type
  const editorBox = h("div");
  const drawEditor = ()=>{
    const n = editing;
    if (!n || !p.nodes.includes(n)) { editorBox.replaceChildren(); return; }
    const t = typeOf(n), rows = [];
    const F = (label, input, hint)=>rows.push(...field(label, input, hint));
    const sec = title=>rows.push(h("div",{class:"proxy-sec"}, title));
    let old = n.name;
    F("名称", h("input",{type:"text", value:n.name||"", spellcheck:false, oninput:e=>{ n.name=e.target.value.trim(); touch(); drawNodes(); },
      onchange:()=>{ rename(old, n.name); old = n.name; drawGroups(); }}), "字母、数字、_ . -（最长 40）；组和规则用名称引用节点，改名会自动跟着改");
    F("类型", inSel({t}, "t", TYPES, v=>{ setType(p, n, v); drawNodes(); drawEditor(); }));
    if (t==="custom"){
      F("Outbound JSON", secretIn(p, n, "json_secret", true), "一个 sing-box 1.14 outbound JSON 对象（例如 shadowtls、hysteria、ssh；type 为 wireguard 时作为 endpoint），tag 由 mr 设置。只写入 secrets.yaml，不会显示。");
    } else {
      F("服务器", inText(n,"server",{placeholder:"IP 或域名", spellcheck:false}));
      F("端口", inNum(n,"port",{min:1,max:65535}));
      if (t==="") F("加密方式", inSel(n,"method",METHODS), "路由器 CPU 有 AES 指令，aes-128-gcm 系列最快");
      if (has(n,"uuid_secret")) F("UUID", secretIn(p,n,"uuid_secret"), "只写入 secrets.yaml，界面不会显示");
      if (t==="socks" || t==="http") F("用户名", optText(n,"username",{placeholder:"不需要认证时留空"}));
      if (has(n,"password_secret")) F("密码", secretIn(p,n,"password_secret"), t==="" ? "2022 系列是 base64 密钥（openssl rand -base64 16，256 位的用 32）" : "只写入 secrets.yaml，界面不会显示");
      if (t==="vless") F("流控 flow", optSel(n,"flow",[["","无"],["xtls-rprx-vision","xtls-rprx-vision"]]), "Vision 要求 TLS 或 REALITY，且传输层为 TCP");
      if (t==="vmess"){
        F("加密 security", optSel(n,"security",[["","auto（默认）"],["aes-128-gcm","aes-128-gcm"],["chacha20-poly1305","chacha20-poly1305"],["none","none"],["zero","zero"]]));
        F("alterId", optNum(n,"alter_id",{max:65535, placeholder:"0"}), "0 = AEAD（推荐）；只有很旧的服务器才需要大于 0");
      }
      if (t==="hysteria2"){
        F("上行 Mbps", optNum(n,"up_mbps",{placeholder:"自动"}), "上下行都不填 = BBR 自动；填了按此带宽发送（Brutal），填实际带宽");
        F("下行 Mbps", optNum(n,"down_mbps",{placeholder:"自动"}));
        F("混淆 obfs", optSel(n,"obfs",[["","无"],["salamander","salamander"]], v=>{ if (!v) delete n.obfs_password_secret; drawEditor(); }));
        if (n.obfs) F("混淆密码", secretIn(p,n,"obfs_password_secret"));
        F("端口跳跃", optText(n,"hop_ports",{placeholder:"例如 20000-30000"}), "服务器开了端口跳跃时填写；多个范围用逗号分隔");
      }
      if (t==="tuic"){
        F("拥塞控制", optSel(n,"congestion_control",[["","cubic（默认）"],["new_reno","new_reno"],["bbr","bbr"]]));
        F("UDP 中继", optSel(n,"udp_relay_mode",[["","native（默认）"],["quic","quic"]]));
      }
      if (has(n,"transport")){
        sec("传输层");
        F("传输", optSel(n,"transport",[["","TCP（无）"],["ws","WebSocket"],["grpc","gRPC"],["http","HTTP/2"],["httpupgrade","HTTPUpgrade"]], v=>{
          if (v!=="grpc") delete n.service_name;
          if (v==="grpc" || !v){ delete n.path; delete n.host; }
          if (v!=="ws") delete n.early_data;
          if (v) delete n.flow;
          touch(); drawNodes(); drawEditor(); }));
        if (["ws","http","httpupgrade"].includes(n.transport)){
          F("路径", optText(n,"path",{placeholder:"/"}));
          F("Host", optText(n,"host",{placeholder:"默认 = SNI / 服务器域名"}));
        }
        if (n.transport==="ws") F("0-RTT early data", optNum(n,"early_data",{max:65535, placeholder:"0"}), "Xray 链接的 path 带 ?ed=2048 时填 2048");
        if (n.transport==="grpc") F("serviceName", optText(n,"service_name"));
      }
      if (has(n,"tls")){
        sec("TLS");
        const always = TLS_ALWAYS.has(t);
        if (!always) F("TLS", optBool(n,"tls", v=>{ if (!v) for (const k of ["sni","alpn","insecure","fingerprint","reality_public_key","reality_short_id","flow"]) delete n[k]; drawNodes(); drawEditor(); }));
        if (always || n.tls){
          F("SNI", optText(n,"sni",{placeholder:"默认 = 服务器域名"}), n.reality_public_key ? "REALITY：填被借用网站的域名（例如 www.microsoft.com）" : null);
          F("ALPN", optList(n,"alpn",{placeholder: t==="tuic"||t==="hysteria2" ? "h3" : "例如 h2, http/1.1"}));
          F("跳过证书验证", optBool(n,"insecure", ()=>drawNodes()), "不安全：只用于自签证书、又拿不到证书的服务器");
          if (has(n,"fingerprint")) F("uTLS 指纹", optSel(n,"fingerprint",[["", n.reality_public_key ? "chrome（REALITY 默认）" : "不模拟（Go TLS）"], ...FPS.map(x=>[x,x])]), "模拟浏览器的 TLS 握手");
          if (has(n,"reality_public_key")){
            F("REALITY 公钥", optText(n,"reality_public_key",{placeholder:"pbk（43 个字符），填了即启用 REALITY", oninput:e=>{ const v=e.target.value.trim(); if (v) n.reality_public_key=v; else { delete n.reality_public_key; delete n.reality_short_id; } touch(); drawNodes(); }}));
            F("REALITY short_id", optText(n,"reality_short_id",{placeholder:"sid，可留空"}));
          }
        }
      }
      if (has(n,"packet_encoding") || has(n,"tcp_only")) sec("UDP");
      if (has(n,"packet_encoding")) F("UDP 封装", optSel(n,"packet_encoding",[["", t==="vless" ? "默认（xudp）" : "默认（不封装）"],["xudp","xudp"],["packetaddr","packetaddr"],["none","不封装"]]));
      if (has(n,"tcp_only")) F("仅 TCP", optBool(n,"tcp_only", ()=>drawNodes()), "服务器不支持 UDP 转发时打开（QUIC 会回落到 TCP）");
    }
    editorBox.replaceChildren(card("编辑节点 · "+(n.name||""), form(...rows), h("button",{class:"btn sm",onclick:()=>{ editing=null; drawNodes(); drawEditor(); }},"关闭")));
  };

  // import: share links or a subscription → preview → add the chosen nodes
  const importBox = h("div");
  const imp = {links:"", url:"", sub:"", subName:"", group:"", overwrite:false, busy:false, res:null};
  const drawImport = ()=>{
    if (!showImport) { importBox.replaceChildren(); return; }
    const subs = p.subscriptions || [];
    const run = async (action, body)=>{
      imp.busy = true; drawImport();
      try {
        const r = await api(action, body);
        const names = new Set([...p.nodes, ...p.groups].map(x=>x.name));
        imp.res = {info:r.info, errors:r.errors||[], nodes:(r.nodes||[]).map(x=>Object.assign(x, {sel:true, name:x.node.name, exists:names.has(x.node.name)}))};
      } catch(e){ toast((action==="proxy.fetch"?"获取订阅失败：":"解析失败：")+e.message, 6000); }
      imp.busy = false; drawImport();
    };
    const fetchSub = s=>{
      const url = S.secrets[s.url_secret];      // not applied yet: the URL is still in the browser
      run("proxy.fetch", url ? {url} : {subscription:s.name});
    };
    const saveSub = ()=>{
      const name = imp.subName.trim();
      if (!/^[A-Za-z0-9_.-]{1,40}$/.test(name)) return toast("订阅名称：字母、数字、_ . -");
      if (!/^https?:\/\/\S+$/.test(imp.url.trim())) return toast("先填写订阅链接");
      if (subs.some(x=>x.name===name)) return toast("已有同名订阅");
      const secret = secretName(name, "sub", usedSecrets(p));
      p.subscriptions = [...subs, {name, url_secret:secret}];
      S.secrets[secret] = imp.url.trim();
      touch(); imp.subName = ""; drawImport(); toast("已保存订阅（链接存入 secrets.yaml），点底部“保存并应用”生效");
    };
    const kids = [
      h("div",{class:"mut",style:"padding:10px 16px 0"},"支持 ss:// vless:// vmess:// trojan:// hysteria2:// hy2:// tuic:// anytls:// socks5:// http(s):// 分享链接，或 base64 订阅（v2rayN 格式；Clash / sing-box 配置文件不支持）。先预览，再选择要添加的节点；密码 / UUID 只写入 secrets.yaml。"),
      h("div",{style:"padding:10px 16px"}, h("textarea",{class:"proxy-ta", rows:5, spellcheck:false, placeholder:"每行一个分享链接，或粘贴 base64 订阅内容",
        oninput:e=>{ imp.links = e.target.value; }}, imp.links),
        h("div",{class:"row",style:"margin-top:8px"}, h("button",{class:"btn p",disabled:imp.busy,onclick:()=>{ if (!imp.links.trim()) return toast("先粘贴分享链接"); run("proxy.parse",{links:imp.links}); }},"解析链接"))),
      h("div",{class:"row",style:"padding:0 16px 10px"},
        h("input",{type:"password", autocomplete:"off", value:imp.url, placeholder:"订阅链接 https://…（含令牌；不保存，除非点“保存为订阅”）", style:"flex:1;min-width:200px", oninput:e=>{ imp.url = e.target.value; }}),
        h("button",{class:"btn",disabled:imp.busy,onclick:()=>{ if (!imp.url.trim()) return toast("先填写订阅链接"); run("proxy.fetch",{url:imp.url.trim()}); }},"获取订阅"),
        h("input",{type:"text", value:imp.subName, placeholder:"订阅名称", style:"max-width:130px", oninput:e=>{ imp.subName = e.target.value; }}),
        h("button",{class:"btn sm",onclick:saveSub},"保存为订阅")),
      subs.length ? roTable(["已保存的订阅","链接",""], subs.map((s,i)=>[h("b",{},s.name),
        S.secrets[s.url_secret] ? h("span",{class:"tag warn"},"未应用") : S.secretsSet[s.url_secret] ? h("span",{class:"tag ok"},"已设置") : h("span",{class:"tag bad"},"未设置"),
        h("span",{style:"white-space:nowrap"}, h("button",{class:"btn sm",disabled:imp.busy,onclick:()=>fetchSub(s)},"获取"), " ",
          h("button",{class:"btn sm d",onclick:()=>{ if (!confirm("删除订阅 "+s.name+"？（链接留在 secrets.yaml，不再被引用）")) return;
            delete S.secrets[s.url_secret]; p.subscriptions = subs.filter((_,k)=>k!==i); if (!p.subscriptions.length) delete p.subscriptions; touch(); drawImport(); }},"删除"))])) : null,
      imp.busy ? h("div",{class:"mut",style:"padding:10px 16px"},"处理中…") : null,
    ];
    const r = imp.res;
    if (r){
      if (r.info){
        const used = (r.info.upload||0)+(r.info.download||0);
        kids.push(h("div",{style:"padding:10px 16px 0"}, "订阅流量：已用 ", h("b",{},fmtBytes(used)), r.info.total?" / "+fmtBytes(r.info.total):"",
          r.info.expire ? "，到期 "+new Date(r.info.expire*1000).toISOString().slice(0,10) : ""));
      }
      const groups = [["","（不加入组）"], ...p.groups.filter(g=>g.name).map(g=>[g.name, "加入组 "+g.name])];
      const selAll = v=>{ for (const x of r.nodes) x.sel = v; drawImport(); };
      kids.push(h("div",{class:"tw"}, h("table",{}, h("thead",{}, h("tr",{}, ["","名称","类型 / 参数","服务器","链接里的名称","提示"].map(x=>h("th",{},x)))),
        h("tbody",{}, r.nodes.length ? r.nodes.map(x=>h("tr",{},
          h("td",{style:"width:1%"}, h("input",{type:"checkbox", checked:x.sel, onchange:e=>{ x.sel = e.target.checked; }})),
          h("td",{style:"min-width:110px"}, h("input",{type:"text", value:x.name, spellcheck:false, oninput:e=>{ x.name = e.target.value.trim(); }})),
          h("td",{}, h("span",{class:"proxy-sum"}, x.summary||"")),
          h("td",{class:"mono"}, x.node.server+":"+x.node.port),
          h("td",{}, x.remark||""),
          h("td",{}, x.exists ? h("span",{class:"tag warn"},"同名") : null, " ", (x.warnings||[]).map(w=>h("div",{class:"mut",style:"font-size:12px"},w)))))
          : h("tr",{}, h("td",{colspan:6,class:"mut"},"（没有可用的节点）"))))));
      if (r.errors.length) kids.push(h("ul",{class:"err proxy-errs"}, r.errors.map(e=>h("li",{}, (e.line?"第 "+e.line+" 行：":"")+e.error))));
      kids.push(h("div",{class:"row",style:"padding:10px 16px"},
        h("button",{class:"btn sm",onclick:()=>selAll(true)},"全选"), h("button",{class:"btn sm",onclick:()=>selAll(false)},"全不选"),
        inSel(imp,"group",groups),
        h("span",{class:"row",title:"同名节点被替换，组和规则里的引用保持不变"}, inBool(imp,"overwrite"), "覆盖同名节点"),
        h("button",{class:"btn p",disabled:!r.nodes.length,onclick:addSelected},"添加选中的节点")));
    }
    importBox.replaceChildren(card("导入链接 / 订阅", kids, h("button",{class:"btn sm",onclick:()=>{ showImport=false; imp.res=null; drawImport(); }},"关闭"), true));
  };
  const addSelected = ()=>{
    const r = imp.res, taken = new Set([...p.nodes, ...p.groups].map(x=>x.name));
    const grp = p.groups.find(g=>g.name===imp.group);
    let added = 0, replaced = 0;
    for (const x of r.nodes){
      if (!x.sel) continue;
      const n = clone(x.node);
      n.name = x.name || n.name;
      const idx = imp.overwrite ? p.nodes.findIndex(o=>o.name===n.name) : -1;
      if (idx<0) n.name = freeName(n.name, taken);
      taken.add(n.name);
      // fresh secret names (unique among the nodes); the values from the links go to S.secrets
      const used = usedSecrets(p, idx>=0 ? p.nodes[idx] : null);
      for (const [k,suf] of Object.entries(SECRET_SUFFIX)) if (n[k]){
        const v = x.secrets[n[k]];
        n[k] = secretName(n.name, suf, used);
        if (v!==undefined) S.secrets[n[k]] = v;
      }
      if (idx>=0){ p.nodes[idx] = n; replaced++; } else { p.nodes.push(n); added++; }
      if (grp){ grp.nodes ||= []; if (!grp.nodes.includes(n.name)) grp.nodes.push(n.name); }
    }
    if (!added && !replaced) return toast("没有选中的节点");
    touch(); imp.res = null; showImport = false; editing = null;
    drawNodes(); drawEditor(); drawImport(); drawGroups();
    toast("已添加 "+added+" 个"+(replaced?"、覆盖 "+replaced+" 个":"")+"节点，点底部“保存并应用”生效", 4000);
  };

  const groupBody = h("tbody");
  const drawGroups = ()=>{
    groupBody.replaceChildren();
    if (!p.groups.length) groupBody.append(h("tr",{}, h("td",{colspan:7,class:"mut"},"（没有节点组：规则可以直接指定节点）")));
    p.groups.forEach((g,i)=>{
      g.nodes ||= [];
      const live = (st.proxies||{})[g.name];
      let cur = live ? h("span",{class:"mono"}, live.now||"-") : h("span",{class:"mut"},"-");
      if (live && g.type==="selector"){
        cur = h("select",{onchange:async e=>{ try { await api("proxy.select",{group:g.name,node:e.target.value}); toast(g.name+" → "+e.target.value); } catch(x){ toast(x.message,4000); } }},
          (live.all||[]).map(x=>h("option",{value:x,selected:x===live.now},x)));
      }
      let old = g.name;
      groupBody.append(h("tr",{},
        h("td",{style:"min-width:90px"}, h("input",{type:"text", value:g.name||"", oninput:e=>{ g.name=e.target.value; touch(); },
          onchange:()=>{ rename(old, g.name); old = g.name; }})),
        h("td",{style:"width:150px"}, inSel(g,"type",[["urltest","自动（延迟最低）"],["selector","手动选择"]], v=>{ if (v==="selector"){ delete g.url; delete g.interval; } touch(); drawGroups(); })),
        h("td",{}, h("div",{class:"proxy-mem"}, p.nodes.filter(n=>n.name).map(n=>h("label",{}, h("input",{type:"checkbox",checked:g.nodes.includes(n.name),onchange:e=>{
          const s=new Set(g.nodes); e.target.checked?s.add(n.name):s.delete(n.name); g.nodes=p.nodes.map(x=>x.name).filter(x=>s.has(x)); touch(); }}), " "+n.name)))),
        h("td",{style:"min-width:140px"}, g.type==="urltest" ? inText(g,"url",{placeholder:"默认 gstatic generate_204"}) : h("span",{class:"mut"},"—")),
        h("td",{style:"width:80px"}, g.type==="urltest" ? inText(g,"interval",{placeholder:"3m"}) : h("span",{class:"mut"},"—")),
        h("td",{}, cur, " ", live ? delayEl(delays[g.name]||live.delay||undefined) : null),
        h("td",{style:"width:1%;white-space:nowrap"}, h("button",{class:"btn sm d",onclick:()=>{ p.groups.splice(i,1); touch(); drawGroups(); }},"删除"))));
    });
  };
  drawNodes(); drawGroups();

  const run = st.running ? h("span",{class:"tag ok"},"sing-box 运行中 "+(st.version||"")) :
    p.enabled ? h("span",{class:"tag bad",title:st.error||""},"sing-box 未运行") : h("span",{class:"tag"},"未启用");
  return h("div",{},
    card("选择性代理", [form(
      ...field("启用", inBool(p,"enabled"), "只有“分流规则”里的域名 / IP 走代理；其它流量不经过代理，继续走内核快速转发和硬件加速。例外设备永不代理。"),
      ...field("仅 IPv4", inBool(p,"ipv4_only"), "代理域名不返回 IPv6（AAAA 为空），客户端改用 IPv4 连接"),
      ...field("日志级别", inSel(p,"log_level",[["","warn（默认）"],["error","error"],["info","info"],["debug","debug"]]), "日志在“系统 → 日志”，标签 sing-box"))], run),
    card("节点", [h("div",{class:"mut",style:"padding:10px 16px 0"},"支持 Shadowsocks、VLESS（REALITY / Vision / uTLS）、VMess、Trojan、Hysteria2、TUIC、AnyTLS、SOCKS5、HTTP(S)，其它协议用“自定义 JSON”。密码 / UUID 只写入 secrets.yaml，界面不会显示。"),
      h("div",{class:"tw"}, h("table",{}, h("thead",{}, h("tr",{}, ["名称","类型","服务器","参数","延迟",""].map(x=>h("th",{},x)))), nodeBody))],
      h("span",{class:"row"}, h("button",{class:"btn sm",disabled:!st.running||!p.nodes.length,onclick:()=>test("")},"全部测速"),
        h("button",{class:"btn sm",onclick:()=>{ showImport = !showImport; drawImport(); if (showImport) importBox.scrollIntoView({behavior:"smooth", block:"start"}); }},"导入链接 / 订阅"),
        h("button",{class:"btn sm p",onclick:addNode},"+ 添加节点")), true),
    editorBox, importBox,
    card("节点组", [h("div",{class:"mut",style:"padding:10px 16px 0"},"自动：定时测延迟，选最快的节点，节点故障自动切换。手动：在“当前”里选择，立即生效（不需要应用）。"),
      h("div",{class:"tw"}, h("table",{}, h("thead",{}, h("tr",{}, ["名称","类型","成员","测试 URL","间隔","当前",""].map(x=>h("th",{},x)))), groupBody))],
      h("button",{class:"btn sm p",onclick:()=>{ const names=new Set([...p.nodes,...p.groups].map(x=>x.name)); p.groups.push({name:uniqueName("group",names),type:"urltest",nodes:p.nodes.map(n=>n.name).filter(Boolean)}); touch(); drawGroups(); }},"+ 添加组"), true),
    card("高级（端口，一般不用改）", form(...PORTS.flatMap(([k,l,d])=>field(l,
      h("input",{type:"number", min:1024, max:65535, value:p[k]||"", placeholder:"默认 "+d, oninput:e=>{ const v=e.target.value; if (v==="") delete p[k]; else p[k]=Number(v); touch(); }}),
      k==="lan_dns_port" ? "LAN 设备的 DNS 被透明重定向到这里" : "只监听本机回环地址，LAN 不可访问")))));
});

// ---------------- 分流规则 ----------------
registerPage("proxy", "proxy-rules", "分流规则", 20, async ()=>{
  const p = P();
  let lists = {files:[], dir:"/etc/mini-router/proxy"};
  try { lists = await api("proxy.lists", {}); } catch(e){}
  const listPath = f=>lists.dir+"/"+f;
  const fileSel = (r, key, ext)=>{
    const opts = [["","（不用列表文件）"], ...lists.files.filter(f=>f.name.endsWith(ext)).map(f=>[listPath(f.name), f.name+"（"+f.entries+" 条）"])];
    return inSel(r, key, opts, v=>{ if(!v) delete r[key]; touch(); });
  };
  const box = h("div");
  const draw = ()=>{
    const outs = outbounds(p);
    box.replaceChildren(...p.rules.map((r,i)=>card(h("span",{}, "规则 "+(i+1)+" · ", h("b",{}, r.name||"(未命名)")),
      h("div",{class:"proxy-rule"}, form(
        ...field("名称", inText(r,"name",{placeholder:"例如 ai"})),
        ...field("出口", inSel(r,"outbound", outs.length?outs:[["","（先添加节点）"]])),
        ...field("域名", lines(r,"domains","每行一个，匹配域名及其所有子域名\n例如 openai.com")),
        ...field("域名列表文件", fileSel(r,"domains_file",".domains")),
        ...field("IP / CIDR", lines(r,"cidrs","每行一个，例如 91.108.4.0/22 或 2001:67c:4e8::/48")),
        ...field("CIDR 列表文件", fileSel(r,"cidr_file",".cidrs")))),
      h("span",{class:"row"},
        h("button",{class:"btn sm",disabled:i===0,onclick:()=>{ [p.rules[i-1],p.rules[i]]=[p.rules[i],p.rules[i-1]]; touch(); draw(); }},"↑"),
        h("button",{class:"btn sm",disabled:i===p.rules.length-1,onclick:()=>{ [p.rules[i+1],p.rules[i]]=[p.rules[i],p.rules[i+1]]; touch(); draw(); }},"↓"),
        h("button",{class:"btn sm d",onclick:()=>{ if(confirm("删除规则 "+(r.name||i+1)+"？")){ p.rules.splice(i,1); touch(); draw(); } }},"删除")))));
    if (!p.rules.length) box.append(h("div",{class:"card"}, h("div",{class:"body mut"},"还没有规则：没有规则时不会有任何流量走代理。")));
  };
  draw();

  // list file editor (files live in /etc/mini-router/proxy; saving needs “保存并应用” to take effect)
  const ed = h("div");
  const openList = async file=>{
    let j = {content:""};
    try { j = await api("proxy.lists",{file}); } catch(e){ return toast(e.message,4000); }
    const ta = h("textarea",{rows:16, spellcheck:false}, j.content||"");
    ed.replaceChildren(card("列表文件 · "+file, [h("div",{class:"mut",style:"margin-bottom:8px"}, (j.path||listPath(file))+" — 每行一个"+(file.endsWith(".cidrs")?" CIDR 或 IP":"域名（含子域名）")+"，# 开头为注释"), ta,
      h("div",{class:"row",style:"margin-top:10px"}, h("button",{class:"btn p",onclick:async()=>{
        try { await api("proxy.lists",{file, content:ta.value, save:true}); toast("已保存，点击底部“保存并应用”生效"); S.orig=""; touch(); lists = await api("proxy.lists",{}); drawFiles(); draw(); }
        catch(e){ toast("保存失败："+e.message+(e.data&&e.data.errors?"\n"+e.data.errors.join("\n"):""), 6000); } }},"保存列表"),
        h("button",{class:"btn",onclick:()=>ed.replaceChildren()},"关闭"))]));
  };
  const nf = {name:"", ext:".domains"};
  const filesEl = h("div");
  const drawFiles = ()=>filesEl.replaceChildren(roTable(["文件","条目","大小",""], lists.files.map(f=>[h("span",{class:"mono"},f.name), f.entries, fmtBytes(f.size),
    h("button",{class:"btn sm",onclick:()=>openList(f.name)},"编辑")])));
  drawFiles();
  return h("div",{},
    card("说明", h("div",{class:"mut"},
      "规则从上到下匹配，先匹配的生效。域名规则用 fake-ip：LAN 设备查询这些域名时拿到 198.18.x.x / fc00:: 假地址，连接由 sing-box 交给代理节点，域名在代理服务器端解析（本地和运营商 DNS 看不到）。IP / CIDR 规则直接按目标地址代理。只对 LAN 区的有线 / 无线设备生效，访客网络、路由器自身和例外设备不受影响。设备若开启了浏览器“安全 DNS (DoH)”，域名规则对它无效。")),
    box,
    h("div",{style:"margin-bottom:18px"}, h("button",{class:"btn p",onclick:()=>{ const o=outbounds(p); p.rules.push({name:uniqueName("rule",new Set(p.rules.map(r=>r.name))), outbound:(o[0]||[""])[0]}); touch(); draw(); }},"+ 添加规则")),
    card("列表文件（"+lists.dir+"）", [filesEl,
      h("div",{class:"row",style:"padding:10px 16px"}, h("span",{class:"mut"},"新建："), inText(nf,"name",{placeholder:"文件名，例如 ai",style:"max-width:180px"}),
        inSel(nf,"ext",[[".domains",".domains（域名）"],[".cidrs",".cidrs（IP 段）"]]),
        h("button",{class:"btn sm",onclick:()=>{ if(!/^[A-Za-z0-9_-]{1,40}$/.test(nf.name)) return toast("文件名只能用字母、数字、_ -"); openList(nf.name+nf.ext); }},"新建并编辑"))], null, true),
    ed);
});

// ---------------- 例外设备 ----------------
registerPage("proxy", "proxy-bypass", "例外设备", 30, async ()=>{
  const p = P();
  let leases = [];
  try { leases = (await api("status")).leases||[]; } catch(e){}
  const known = new Map();
  for (const x of S.cfg.dhcp.hosts||[]) if (x.mac) known.set(x.mac.toLowerCase(), {name:x.name||x.mac, ip:x.ip, tag:"静态"});
  for (const l of leases) if (l.mac && !known.has(l.mac.toLowerCase())) known.set(l.mac.toLowerCase(), {name:l.name&&l.name!=="*"?l.name:l.mac, ip:l.ip, tag:"租约"});
  const t = etable(p.bypass, [{k:"name",l:"名称"},{k:"mac",l:"MAC",ph:"aa:bb:cc:dd:ee:ff"}], {name:"",mac:""}, {noMove:true});
  const pick = {v:""};
  const picker = ()=>{
    const have = new Set(p.bypass.map(b=>(b.mac||"").toLowerCase()));
    const opts = [["","从 DHCP 设备中选择…"], ...[...known].filter(([m])=>!have.has(m)).map(([m,d])=>[m, d.name+" · "+(d.ip||"")+" · "+m+"（"+d.tag+"）"])];
    return inSel(pick,"v",opts, m=>{ if(!m) return; const d=known.get(m); p.bypass.push({name:d.name, mac:m}); pick.v=""; touch(); t.redraw(); pickBox.replaceChildren(picker()); });
  };
  const pickBox = h("span",{}, picker());
  return h("div",{},
    card("例外设备", [h("div",{class:"mut",style:"padding:10px 16px 0"},
      "例外设备永远不走代理：它的 DNS 由主 dnsmasq 正常解析（真实 IP，不会拿到 fake-ip），IPv4 / IPv6 流量都不进入 sing-box。按 MAC 识别，所以动态分配的 IPv4 和 IPv6（SLAAC / 隐私地址）都生效。设备如果开了“私有 Wi-Fi 地址”（随机 MAC），请对本网络关闭。"),
      t.el, h("div",{class:"row",style:"padding:10px 16px"}, pickBox)], t.add, true));
});

// ---------------- 代理状态 ----------------
registerPage("proxy", "proxy-status", "代理状态", 40, async ()=>{
  const p = P();
  const top = h("div"), connBox = h("div"), connTitle = h("span",{},"代理连接");
  const q = {v:""};
  let prev = null, last = {};
  const drawConns = ()=>{
    const all = last.connections||[];
    const conns = all.filter(c=>!q.v || [c.src,c.dst,(c.chains||[]).join(" "),c.rule].join(" ").toLowerCase().includes(q.v));
    connTitle.textContent = "代理连接（"+conns.length+((last.connections_total||0)>all.length?"，共 "+last.connections_total:"")+"）";
    connBox.replaceChildren(roTable(["来源","目标","出口","规则","↑","↓","时长"], conns.map(c=>[
      h("span",{class:"mono"},c.src), h("span",{class:"mono"},c.dst), (c.chains||[]).slice().reverse().join(" → "), h("span",{class:"mut"},c.rule||""),
      fmtBytes(c.up), fmtBytes(c.down), fmtDur(c.age)])));
  };
  // the filter stays outside the refreshed part so it keeps focus
  const filter = h("input",{type:"text",placeholder:"过滤（来源 / 目标 / 出口）",style:"max-width:240px",oninput:e=>{ q.v=e.target.value.toLowerCase(); drawConns(); }});
  const draw = async ()=>{
    const st = await status();
    last = st; learnSecrets(st);
    const now = Date.now()/1000;
    let rate = null;
    if (prev && st.running && now>prev.t) rate = {up:Math.max(0,(st.upload_total-prev.u)*8/(now-prev.t)), down:Math.max(0,(st.download_total-prev.d)*8/(now-prev.t))};
    prev = st.running ? {u:st.upload_total, d:st.download_total, t:now} : null;
    const stat = (l,v,s)=>h("div",{class:"card stat"}, h("div",{class:"l"},l), h("div",{class:"v"},v), s?h("div",{class:"s"},s):null);
    const px = st.proxies||{};
    const outs = [...p.groups.map(g=>[g.name, px[g.name]]), ...p.nodes.map(n=>[n.name, px[n.name]])].filter(x=>x[0]);
    top.replaceChildren(
      h("div",{class:"grid",style:"margin-bottom:18px"},
        stat("状态", !p.enabled?"未启用":st.running?"运行中":"未运行", st.running?"sing-box "+(st.version||""):(st.error||"")),
        stat("代理连接", st.running?String(st.connections_total||0):"-", "只统计走代理的连接"),
        stat("实时", rate?"↓ "+fmtRate(rate.down):"-", rate?"↑ "+fmtRate(rate.up):""),
        stat("累计", st.running?"↓ "+fmtBytes(st.download_total):"-", st.running?"↑ "+fmtBytes(st.upload_total)+" · 内存 "+fmtBytes(st.memory):"")),
      card("出口", roTable(["名称","类型","当前节点","延迟"], outs.map(([n,x])=>[h("b",{},n), x?x.type:"-", x&&x.now?h("span",{class:"mono"},x.now):"-", delayEl(x&&x.delay?x.delay:undefined)])), null, true));
    drawConns();
  };
  await draw();
  S.timer = setInterval(()=>draw().catch(()=>{}), 3000);
  return h("div",{}, top, card(connTitle, connBox, filter, true));
});
})();
