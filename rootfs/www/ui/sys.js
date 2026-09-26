// mini-router web UI — sys module pages: 服务 (group services); 系统设置, 管理与 SSH, 计划任务,
// 备份与升级, 日志, 网络诊断 (group system); 体检与事件 (group status: mr doctor, the event log,
// notifications). Uses only the helpers in ui/core.js; see docs/MODULES.md and docs/modules/sys.md.
"use strict";
(()=>{
addCSS(`
.sys-grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fill,minmax(min(340px,100%),1fr))}
.sys-grid>.card{margin-bottom:0}
.sys-sp{height:14px}
.sys-svc h2 .tag{font-weight:400}
.sys-note{color:var(--mut);font-size:12px;margin-top:8px}
.sys-warnbox{border:1px solid rgba(201,138,11,.45);background:rgba(201,138,11,.08);color:var(--warn);border-radius:6px;padding:8px 10px;margin:8px 0;font-size:13px}
.sys-errbox{border:1px solid rgba(214,69,69,.45);background:rgba(214,69,69,.08);color:var(--bad);border-radius:6px;padding:8px 10px;margin:8px 0;font-size:13px;white-space:pre-wrap;word-break:break-word}
.sys-keys{min-height:120px;white-space:pre;overflow-x:auto}
.sys-log{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;max-height:70vh;overflow:auto;background:var(--code);border:1px solid var(--line);border-radius:6px;padding:4px 0}
.sys-log div{padding:1px 10px;white-space:pre-wrap;word-break:break-all}
.sys-log .t{color:var(--mut)}
.sys-log .l0,.sys-log .l1,.sys-log .l2,.sys-log .l3{color:var(--bad)}
.sys-log .l4{color:var(--warn)}
.sys-log .l7{color:var(--mut)}
.sys-log .g{color:var(--acc)}
.sys-filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.sys-filters select,.sys-filters input[type=text]{width:auto;min-width:120px;flex:1 1 140px;max-width:260px}
.sys-prog{height:8px;background:var(--line);border-radius:4px;overflow:hidden;margin:8px 0}
.sys-prog i{display:block;height:100%;width:0;background:var(--acc);transition:width .2s}
.sys-days{display:flex;gap:3px;flex-wrap:wrap}
.sys-days label{display:inline-flex;align-items:center;justify-content:center;min-width:32px;height:28px;border:1px solid var(--line);border-radius:4px;cursor:pointer;user-select:none;font-size:12px}
.sys-days label.on{background:var(--acc);border-color:var(--acc);color:var(--acc-fg)}
.sys-days input{display:none}
.sys-off td:not(.sys-keep){opacity:.45}
.sys-clock{font-variant-numeric:tabular-nums}
.sys-file{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.sys-file input[type=file]{max-width:100%;font-size:13px}
.sys-chan{border:1px solid var(--line);border-radius:6px;padding:10px 12px;margin:10px 16px}
.sys-fix{font-size:12px;white-space:pre-wrap;word-break:break-word}
.sys-ev{padding:8px 16px;border-top:1px solid var(--line)}
.sys-ev .row{gap:8px}
.sys-ev .m{margin-top:3px;word-break:break-word}
`);

// ---------- shared bits ----------
const mono = s => h("span",{class:"mono"}, s);
const dash = v => (v===undefined || v===null || v==="") ? h("span",{class:"mut"},"—") : v;
const C = ()=>{
  const c = S.cfg;
  c.system ||= {}; c.system.ntp ||= []; c.system.sysctl ||= {};
  c.services ||= {};
  for (const k of ["tailscale","dstatus","stubby","ssh","panel"]) c.services[k] ||= {};
  c.services.ssh.authorized_keys ||= [];
  c.schedules ||= [];
  return c;
};
const errText = e => e && e.data && e.data.errors ? e.data.errors.join("\n") : (e && e.message) || String(e);
function restartBtn(name, label){
  return h("button",{class:"btn sm",onclick:async()=>{
    try { await api("service",{name,op:"restart"}); toast("已重启 "+name); } catch(e){ toast(e.message,4000); } }}, label||"重启");
}
function b64(u8){ let s=""; for (let i=0;i<u8.length;i+=0x8000) s+=String.fromCharCode.apply(null, u8.subarray(i,i+0x8000)); return btoa(s); }
function unb64(s){ const bin=atob(s); const u=new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u; }
function download(name, u8, type){
  const url = URL.createObjectURL(new Blob([u8],{type:type||"application/octet-stream"}));
  const a = h("a",{href:url, download:name, style:"display:none"}); document.body.append(a); a.click();
  setTimeout(()=>{ a.remove(); URL.revokeObjectURL(url); }, 1000);
}
const sleep = ms => new Promise(r=>setTimeout(r, ms));

// ---------- DDNS (services.ddns; no daemon: WAN hooks + crond run `mr ddns sync`) ----------
const ago = t => t ? fmtDur(Date.now()/1000 - t)+"前" : "—";
// provider -> [name, the keys it takes (docs/modules/sys.md), default secret name, how to get the credentials]
const DDNS_P = {
  cloudflare:["Cloudflare", ["zone","token_secret","ttl"], "cf_ddns_token", "Token：My Profile › API Tokens › “Edit zone DNS” 模板，只授权这个域。只改记录的地址，代理（橙色云）等设置不变。"],
  alidns:["阿里云 AliDNS", ["zone","key_id","key_secret","ttl"], "ali_dns_key", "RAM 访问控制新建用户，只授予 AliyunDNSFullAccess，用它的 AccessKey。线路和 TTL 保持不变。"],
  dnspod:["腾讯云 DNSPod", ["zone","key_id","key_secret","ttl"], "tc_dns_key", "访问管理 CAM 新建子用户，授予 QcloudDNSPodFullAccess，用它的 API 密钥（SecretId / SecretKey）。线路和 TTL 保持不变。"],
  duckdns:["DuckDNS", ["token_secret"], "duck_token", "域名写 名字.duckdns.org；Token 在 duckdns.org 登录后的首页。"],
  dyndns2:["dyndns2（No-IP、Dynu、deSEC…）", ["url","username","password_secret"], "ddns_password", "服务商的更新地址和账号（deSEC 的密码是 Token）。"],
  webhook:["Webhook", ["url","method","token_secret"], "ddns_hook_token", "{name} {type} {ip} 换成域名、A / AAAA 和地址，{token} 换成 Token（URL 里没有 {token} 时 Token 放在 Authorization: Bearer 头）；POST 还带 JSON {name, type, ip}。"],
};
const DDNS_KEYS = ["zone","token_secret","key_id","key_secret","url","username","password_secret","method","ttl"];
// an ipv4 / ipv6 value as [mode, argument]
const addrMode = (v, v6)=>{
  v = v || (v6 ? "off" : "active");
  if (v.startsWith("url:") || v.startsWith("mac:")) return [v.slice(0,3), v.slice(4)];
  if (v==="off" || v==="active" || v==="router") return [v, ""];
  if (v6 && v.startsWith("::")) return ["iid", v];
  if (v6 || /^[0-9.]+$/.test(v)) return ["ip", v];
  return ["wan:"+v, ""];
};
// a url: source by its host (the status table stays narrow)
const srcShort = s=>{ try { return s.startsWith("url:") ? "url:"+new URL(s.slice(4)).host : s; } catch(e){ return s; } };
const addrText = (v, v6)=>{
  const [m, a] = addrMode(v, v6);
  return {off:dash(""), active:"在用的 WAN", router:"路由器"}[m] || mono(m.startsWith("wan:") ? m.slice(4) : m==="url"||m==="mac" ? srcShort(m+":"+a) : a);
};
function addrIn(c, o, key, v6){
  const [m0, a0] = addrMode(o[key], v6), st = {m:m0, a:a0};
  const PH = {url: v6 ? "https://api6.ipify.org" : "https://api.ipify.org", mac:"aa:bb:cc:dd:ee:ff", ip: v6 ? "2001:db8::10" : "203.0.113.10", iid:"::10"};
  const opts = v6 ? [["off","不更新"],["router","路由器自己的地址"],["iid","LAN 设备：前缀 + 后缀"],["mac","LAN 设备：按 MAC"],["url","外部查询（URL）"],["ip","固定地址"]]
    : [["active","在用的 WAN（自动）"], ...(c.wan||[]).map(w=>["wan:"+w.name, "WAN "+w.name]), ["url","外部查询（URL）"],["mac","LAN 设备：按 MAC"],["ip","固定地址"],["off","不更新"]];
  const box = h("span",{class:"row"});
  const set = ()=>{ o[key] = st.m.startsWith("wan:") ? st.m.slice(4) : st.m==="url"||st.m==="mac" ? st.m+":"+st.a.trim() : PH[st.m] ? st.a.trim() : st.m; };
  const draw = ()=>box.replaceChildren(...[
    h("select",{style:"width:auto", onchange:e=>{ st.m = e.target.value; st.a = ""; set(); draw(); }}, opts.map(([v,l])=>h("option",{value:v, selected:v===st.m}, l))),
    PH[st.m] ? h("input",{type:"text", value:st.a, placeholder:PH[st.m], style:"flex:1 1 150px;min-width:0", oninput:e=>{ st.a = e.target.value; set(); }}) : null].filter(Boolean));
  draw();
  return box;
}
function editDDNS(c, orig, save){
  const x = clone(orig);
  x.provider ||= "cloudflare";
  const tx = (k, ph)=>h("input",{type:"text", value:x[k]??"", placeholder:ph||"", oninput:e=>{ x[k] = e.target.value.trim(); if (!x[k]) delete x[k]; }});
  const pbox = h("div",{style:"display:contents"});
  const drawP = ()=>{
    const P = DDNS_P[x.provider] || DDNS_P.cloudflare, ks = P[1], sk = ks.find(k=>k.endsWith("_secret"));
    for (const k of DDNS_KEYS) if (!ks.includes(k)) delete x[k];
    if (x.provider!=="webhook") x[sk] ||= P[2];
    if (ks.includes("method")) x.method ||= "GET";
    const f = (k, l, ph, hint)=>ks.includes(k) ? field(l, tx(k, ph), hint) : [];
    const nameIn = tx(sk, P[2]), secIn = inSecret(x, sk);
    // the webhook's token is optional: typing one gives it the default name
    secIn.addEventListener("focus", ()=>{ if (!x[sk]){ x[sk] = P[2]; nameIn.value = P[2]; } });
    pbox.replaceChildren(...[
      ...f("zone", "Zone（域）", "example.com", "服务商那里的域名，上面的域名在它下面"),
      ...f("key_id", x.provider==="alidns" ? "AccessKey ID" : "SecretId"),
      ...f("url", x.provider==="webhook" ? "URL" : "更新地址", x.provider==="webhook" ? "https://example.com/ddns?host={name}&ip={ip}" : "https://dynupdate.no-ip.com/nic/update"),
      ...f("username", "用户名"),
      ...(ks.includes("method") ? field("方法", inSel(x,"method",["GET","POST"])) : []),
      ...field("密钥引用名", nameIn, "secrets.yaml 里的名字，几条记录可以共用"),
      ...field({token_secret:"Token", key_secret: x.provider==="alidns" ? "AccessKey Secret" : "SecretKey", password_secret:"密码"}[sk], secIn),
      ...(ks.includes("ttl") ? field("TTL", inNum(x,"ttl",{min:0, max:86400, style:"max-width:110px"}), "0 = 保持记录原来的（新建：服务商默认）") : []),
      h("span"), h("div",{class:"hint"}, P[3])].filter(Boolean)); // field() gives null for "no hint"
  };
  drawP();
  const m = modal(orig.name ? "编辑 DDNS · "+orig.name : "添加 DDNS 记录", form(
      ...field("域名", tx("name","home.example.com")),
      ...field("服务商", inSel(x,"provider",Object.entries(DDNS_P).map(([k,v])=>[k,v[0]]), drawP)),
      pbox,
      ...field("A 记录（IPv4）", addrIn(c, x, "ipv4", false), "运营商内网 / CGNAT 地址不会发布；外部查询从这条 WAN 发出，适合路由器在光猫后面"),
      ...field("AAAA（IPv6）", addrIn(c, x, "ipv6", true), "LAN 设备的地址外网要访问，还要在 防火墙 › IPv6 入站 放行")),
    [h("button",{class:"btn",onclick:()=>m.remove()},"取消"), h("button",{class:"btn p",onclick:()=>{
      if (!x.name) return toast("请填写域名");
      for (const k of ["ipv4","ipv6"]) if (/^(url|mac):$/.test(x[k]||"") || x[k]==="") return toast("请填写地址来源的内容", 4000);
      if (!x.ttl) delete x.ttl;
      if (x.provider==="webhook" && x.token_secret && !S.secrets[x.token_secret] && !S.secretsSet[x.token_secret]) delete x.token_secret;
      m.remove(); save(x); }},"确定")]);
}
function ddnsCard(c, st){
  const sv = c.services;
  const dd = sv.ddns || {enabled:false, interval:10};
  const recs = dd.records || [];
  // the section (and its list) appears in router.yaml on the first edit, not by opening this page
  const attach = ()=>{ if (!dd.records) dd.records = recs; if (!sv.ddns) sv.ddns = dd; touch(); };
  const tb = h("tbody");
  const draw = ()=>tb.replaceChildren(...(recs.length ? recs.map((x,i)=>h("tr",{},
    h("td",{}, mono(x.name||""), h("div",{class:"mut",style:"font-size:12px"}, (DDNS_P[x.provider||"cloudflare"]||[x.provider])[0]),
      h("div",{class:"row",style:"margin-top:4px"},
        h("button",{class:"btn sm",onclick:()=>editDDNS(c, x, y=>{ recs[i] = y; attach(); draw(); })},"编辑"),
        h("button",{class:"btn sm d",onclick:()=>{ recs.splice(i,1); attach(); draw(); }},"删除"))),
    h("td",{}, h("div",{}, "A ", addrText(x.ipv4, false)), h("div",{}, "AAAA ", addrText(x.ipv6, true)))))
    : [h("tr",{}, h("td",{colspan:2, class:"mut"},"（空）"))]));
  draw();
  const add = h("button",{class:"btn sm p",onclick:()=>editDDNS(c, {name:"", provider:"cloudflare", ipv4:"active", ipv6:"off"}, y=>{ recs.push(y); attach(); draw(); })},"+ 添加");
  const stBox = h("div");
  const state = r=>{
    if (r.error) return h("span",{class:"err",title:r.error,style:"display:inline-block;min-width:220px"}, r.stopped ? "密钥被拒绝，已停止自动重试（改配置或点“立即更新”）：" : "失败（"+ago(r.error_at)+"）：", r.error);
    if (!r.local) return dash("");
    return r.published===r.local ? h("span",{class:"tag ok"},"已同步") : h("span",{class:"tag warn"},"待更新");
  };
  const drawSt = rows=>{
    rows = rows||[];
    stBox.replaceChildren(rows.length ? roTable(["域名","类型","来源","本机地址","已发布","上次成功","状态"], rows.map(r=>[
      mono(r.name), r.type, mono(srcShort(r.source||"")), r.local ? mono(r.local) : h("span",{class:"mut"}, r.note||"—"),
      r.published ? mono(r.published) : dash(""), ago(r.last_ok), state(r)])) :
      h("div",{class:"mut",style:"padding:10px 16px"}, "（保存并应用后显示状态）"));
  };
  drawSt(st && st.records);
  const upd = h("button",{class:"btn sm",onclick:async e=>{
    e.target.disabled = true;
    try { const r = await api("sys.ddnsupdate",{force:true}); drawSt(r.records); toast("已检查并更新"); }
    catch(err){ toast(err.message, 5000); } finally { e.target.disabled = false; } }}, "立即更新");
  return card("DDNS 动态域名", [
    h("div",{style:"padding:10px 16px 0"}, form(
      ...field("启用", inBool(dd,"enabled",attach)),
      ...field("定时检查（分钟）", h("input",{type:"number", min:0, max:60, value:dd.interval??10, style:"max-width:110px",
        oninput:e=>{ dd.interval = e.target.value===""?10:Number(e.target.value); attach(); }}),
        "WAN 上线 / 续约 / IPv6 前缀变化时立即更新；此外每隔几分钟核对一次（地址没变就不联网），0 = 只靠 WAN 事件。每天还会向服务商核对一次记录。"))),
    h("div",{class:"sys-note",style:"padding:0 16px"},
      "服务商：Cloudflare、阿里云、DNSPod、DuckDNS、dyndns2（No-IP 等）或 Webhook。密钥只存在路由器的 secrets.yaml 里。地址变化会记入事件，按“通知”的设置推送。"),
    h("div",{class:"tw"}, h("table",{}, h("thead",{}, h("tr",{}, ["域名 / 服务商","地址来源"].map(x=>h("th",{},x)))), tb)),
    h("div",{class:"row",style:"padding:10px 16px 0"}, h("b",{},"状态"), h("span",{class:"sp",style:"flex:1"}), upd),
    stBox], add, true);
}

// ---------- HTTPS 反向代理 (services.edge: `mr edge serve` = service mr-edge; certificates: `mr edge renew`) ----------
const EDGE_BLANK = ()=>({name:"", host:"", to:"http://192.168.1.10:5000"});
function edgeCard(c, st, svc){
  const sv = c.services;
  const ed = sv.edge || {enabled:false, port:443};
  const acme = ed.acme || {token_secret:"cf_ddns_token"};
  const routes = ed.routes || [];
  // the section appears in router.yaml on the first edit, not by opening this page
  const attach = ()=>{ if (!ed.routes) ed.routes = routes; if (!ed.acme) ed.acme = acme; if (!sv.edge) sv.edge = ed; touch(); };
  const tx = (o, k, ph, w)=>h("input",{type:"text", value:o[k]??"", placeholder:ph||"", style:w?"max-width:"+w:null, oninput:e=>{ o[k]=e.target.value; attach(); }});
  const sw = (checked, set)=>h("label",{class:"sw"}, h("input",{type:"checkbox", checked, onchange:e=>{ set(e.target.checked); attach(); }}), h("span"));
  // DNS-01 credentials: the same kind as a DDNS record of that provider (the same secret works)
  const acmeBox = h("div",{style:"display:contents"});
  const drawAcme = ()=>{
    const p = acme.provider || "cloudflare";
    if (p==="cloudflare"){ delete acme.key_id; delete acme.key_secret; acme.token_secret ||= "cf_ddns_token"; }
    else { delete acme.token_secret; acme.key_secret ||= DDNS_P[p][2]; }
    acmeBox.replaceChildren(...(p==="cloudflare" ? [
      ...field("Token 引用名", tx(acme,"token_secret","cf_ddns_token","200px"), "和 DDNS 用同一种 Token（Zone › DNS › Edit），可以直接用同一个"),
      ...field("API Token", inSecret(acme,"token_secret"))] : [
      ...field(p==="alidns" ? "AccessKey ID" : "SecretId", tx(acme,"key_id","","260px"), "和 DDNS 用同一套 API 密钥"),
      ...field("密钥引用名", tx(acme,"key_secret",DDNS_P[p][2],"200px")),
      ...field(p==="alidns" ? "AccessKey Secret" : "SecretKey", inSecret(acme,"key_secret"))]).filter(Boolean));
  };
  drawAcme();
  const t = etable(routes, [
    {k:"name", l:"名称", ph:"nas", w:"90px"},
    {k:"host", l:"域名", ph:"nas.example.com"},
    {k:"to", l:"转发到（内网服务）", ph:"http://192.168.1.10:5000"},
    {k:"allow", l:"允许访问", t:"list", ph:"留空 = 所有人；lan, 203.0.113.0/24"},
  ], ()=>{ attach(); return EDGE_BLANK(); }, {noMove:true});
  const days = x => Math.floor((x - Date.now()/1000)/86400);
  const allowText = a => !a || !a.length ? "所有人" : a.map(x=>x==="lan"?"局域网":x).join("、");
  const certState = x=>{
    if (x.error) return h("span",{class:"err",title:x.error}, "失败（"+ago(x.error_at)+"）：", x.error);
    const d = x.not_after ? days(x.not_after) : 0;
    switch (x.state){
      case "ok": return h("span",{class:"tag "+(d<14?"warn":"ok")}, "有效，剩 "+d+" 天");
      case "due": return h("span",{class:"tag warn"}, "待续期（剩 "+d+" 天）");
      case "missing": return h("span",{class:"tag warn"}, "尚未签发");
      case "expired": return h("span",{class:"tag bad"}, "已过期");
    }
    return h("span",{class:"tag warn"}, x.state==="names changed"?"域名已变，待重新签发":x.state==="other CA"?"测试 / 正式 CA 已切换，待重新签发":x.state);
  };
  const stBox = h("div");
  const draw = s=>{
    if (!s || !s.enabled){ stBox.replaceChildren(h("div",{class:"mut",style:"padding:10px 16px"}, "（保存并应用后显示状态）")); return; }
    stBox.replaceChildren(...[
      roTable(["站点","域名","转发到","允许","外网可达","请求","502"], (s.routes||[]).map(r=>[r.name, mono(r.host), mono(r.to), allowText(r.allow),
        r.wan ? h("span",{class:"tag warn"},"是") : h("span",{class:"mut"},"否"), s.serving ? String(r.requests||0) : dash(""), s.serving ? String(r.errors||0) : dash("")])),
      roTable(["证书","包含域名","状态","到期","上次签发"], (s.certs||[]).map(x=>[mono(x.name), mono((x.domains||[]).join(" ")), certState(x),
        x.not_after ? new Date(x.not_after*1000).toLocaleDateString() : dash(""), ago(x.last_ok)])),
      s.renewing ? h("div",{class:"sys-note",style:"padding:0 16px 10px"}, "正在申请证书（通常 1–2 分钟）…") : null].filter(Boolean));
  };
  draw(st);
  const poll = async (left)=>{
    try { const s = await api("sys.edge"); draw(s); if (s.renewing && left > 0) setTimeout(()=>poll(left-1), 5000); } catch(e){}
  };
  const renew = h("button",{class:"btn sm",onclick:async e=>{
    e.target.disabled = true;
    try { await api("sys.edgerenew",{}); toast("已开始申请 / 续期证书"); setTimeout(()=>poll(60), 3000); }
    catch(err){ toast(err.message, 5000); } finally { e.target.disabled = false; } }}, "立即申请 / 续期");
  const run = svc ? h("span",{class:"tag "+(svc.running?"ok":(svc.wanted?"bad":""))}, !svc.installed?"未安装":svc.running?"运行中":"已停止") : null;
  return card("HTTPS 反向代理（自动证书）", [
    h("div",{style:"padding:10px 16px 0"}, form(
      ...field("启用", inBool(ed,"enabled",attach), "mr-edge：按域名把 HTTPS 转发到内网服务；证书由 Let's Encrypt 通过 DNS 验证（Cloudflare、阿里云或 DNSPod）自动申请、每天检查续期（不需要 80 端口）"),
      ...field("HTTPS 端口", h("input",{type:"number", min:1, max:65535, value:ed.port??443, style:"max-width:110px",
        oninput:e=>{ ed.port = e.target.value===""?443:Number(e.target.value); attach(); }})),
      ...field("对外网开放", sw(!!ed.open, v=>{ ed.open = v; }), "打开后外网（IPv4 + IPv6）能访问这个端口；每个站点还可以用“允许访问”限制来源。不要再在防火墙里开放同一端口（会被拒绝）"),
      ...field("局域网解析", sw(ed.lan_dns!==false, v=>{ if (v) delete ed.lan_dns; else ed.lan_dns = false; }), "局域网里这些域名直接解析到路由器（不绕公网，WAN 断了也能用）"),
      ...field("证书邮箱", tx(acme,"email","可留空","260px")),
      ...field("DNS 验证", inSel(acme,"provider",["cloudflare","alidns","dnspod"].map(k=>[k, DDNS_P[k][0]]), ()=>{ attach(); drawAcme(); })),
      acmeBox,
      ...field("通配符证书", h("input",{type:"text", value:(acme.wildcard||[]).join(", "), placeholder:"example.com", style:"max-width:260px",
        oninput:e=>{ acme.wildcard = e.target.value.split(/[\s,]+/).filter(Boolean); attach(); }}), "这些域名下一级的站点共用一张 *.域名 证书（子域名不会出现在证书公开日志里）；其余每个域名一张"),
      ...field("测试 CA", sw(!!acme.staging, v=>{ acme.staging = v; }), "Let's Encrypt staging：证书不受浏览器信任，只用来试配置"))),
    h("div",{class:"sys-note",style:"padding:0 16px"},
      "“转发到”写内网服务的 IP 和端口（http:// 或 https://，https 不校验内网自签证书）。“允许访问”：lan = 局域网和 Tailscale；也可以写 IP / 网段；留空 = 所有能到达端口的人。"),
    t.el,
    h("div",{class:"row",style:"padding:10px 16px 0"}, h("b",{},"状态"), run, h("span",{class:"sp",style:"flex:1"}), renew),
    stBox], t.add, true);
}

// ---------- 服务 ----------
registerPage("services", "services", "服务", 10, async ()=>{
  const c = C(), sv = c.services;
  let d = {services:[], others:[]}, dns = null, edge = null;
  try { [d, dns, edge] = await Promise.all([api("sys.services"), api("sys.ddns").catch(()=>null), api("sys.edge").catch(()=>null)]); } catch(e){ toast("读取服务状态失败："+e.message, 4000); }
  const row = Object.fromEntries((d.services||[]).map(x=>[x.name,x]));
  const state = name=>{
    const r = row[name];
    if (!r) return null;
    if (!r.installed) return h("span",{class:"tag warn"},"未安装");
    return h("span",{class:"tag "+(r.running?"ok":(r.wanted?"bad":""))}, r.running?"运行中":"已停止");
  };
  const dot = name=>h("span",{class:"dot "+(row[name]&&row[name].running?"ok":"bad")});
  const canRestart = name=>row[name] && row[name].installed && row[name].wanted;
  const svcCard = (title, name, body, extra)=>h("div",{class:"card sys-svc"},
    h("h2",{}, dot(name), title, h("span",{class:"sp"}), state(name), canRestart(name)?restartBtn(name):null),
    h("div",{class:"body"}, body, extra||null));

  const ts = d.tailscale || null;
  const tsBody = [form(
    ...field("启用", inBool(sv.tailscale,"enabled")),
    ...field("UDP 端口", inNum(sv.tailscale,"port",{min:1,max:65535}), "在所有 WAN 上放行，用于直连"),
  )];
  if (ts) tsBody.push(h("dl",{class:"kv",style:"margin-top:12px"},
    h("dt",{},"状态"), h("dd",{}, ts.state||"-"),
    h("dt",{},"本机地址"), h("dd",{class:"mono"}, ts.self&&ts.self.ips ? ts.self.ips.join("  ") : "-"),
    h("dt",{},"Tailnet"), h("dd",{}, ts.tailnet||ts.suffix||"-"),
    h("dt",{},"节点"), h("dd",{}, (ts.peers_online??"-")+" 在线 / "+(ts.peers_total??"-")),
    ts.error ? [h("dt",{},"错误"), h("dd",{class:"err"}, ts.error)] : null));
  if (ts && ts.auth_url) tsBody.push(h("div",{class:"sys-warnbox"}, "此路由器尚未登录 Tailscale：", h("a",{href:ts.auth_url,target:"_blank",rel:"noopener noreferrer"},"点此登录"), "，登录后刷新本页。"));

  const cards = [
    svcCard("Tailscale", "tailscale", tsBody),
    svcCard("dstatus 探针", "dstatus-agent", form(...field("启用", inBool(sv.dstatus,"enabled"), "配置文件 /etc/dstatus-agent/config.yaml（没有则不启动）"))),
    svcCard("stubby（DNS over TLS）", "stubby", form(...field("启用", inBool(sv.stubby,"enabled"), "DNS 页面的上游选 DoT 或分流到 127.0.0.1#5453 时需要"))),
    svcCard("SSH (dropbear)", "dropbear", form(...field("启用", inBool(sv.ssh,"enabled")),
      h("span"), h("div",{}, "端口 ", mono(String(sv.ssh.port||22)), " · ", h("a",{href:"#admin"},"SSH 设置与公钥 →")))),
    svcCard("Web 管理 (httpd)", "mr-panel", form(...field("启用", inBool(sv.panel,"enabled"),
      h("span",{class:"err"},"关闭后本页面也无法访问，只能用 SSH 管理")))),
    svcCard("NTP (busybox ntpd)", "ntpd", h("div",{}, "始终启用。", c.system.ntp_server?"同时为局域网提供时间服务。":"", " ", h("a",{href:"#system"},"时间设置 →"))),
    svcCard("计划任务 (crond)", "crond", h("div",{}, "有启用的计划任务或 DDNS 定时检查时自动启用（当前 ", String(c.schedules.filter(x=>x.enabled!==false).length), " 个任务）。 ", h("a",{href:"#schedules"},"计划任务 →"))),
    svcCard("zram 压缩内存", "mr-zram", form(...field("启用", inBool(c.system,"zram"), "内存的 1/4 做压缩交换（zstd）"))),
  ];
  const peers = ts && ts.peers || [];
  const peerTable = ts ? card("Tailscale 节点（"+peers.length+"）", roTable(["设备","地址","系统","状态","连接","流量 ↓/↑","最后在线"],
    peers.map(p=>[
      h("span",{}, h("b",{}, p.host||"-"), p.exit_node?h("span",{class:"tag ok",style:"margin-left:6px"},"出口节点"):null,
        (p.routes&&p.routes.length)?h("div",{class:"mut mono"}, p.routes.join(" ")):null),
      mono((p.ips||[]).join("\n")), p.os||"-",
      h("span",{class:"tag "+(p.online?"ok":"")}, p.online?"在线":"离线"),
      p.online ? (p.direct ? h("span",{title:p.direct},"直连") : h("span",{class:"mut"},"中继 "+(p.relay||""))) : dash(""),
      (p.rx||p.tx) ? fmtBytes(p.rx)+" / "+fmtBytes(p.tx) : dash(""),
      p.online ? "现在" : (p.last_seen && !p.last_seen.startsWith("0001") ? new Date(p.last_seen).toLocaleString() : "-"),
    ])), null, true) : null;
  const others = d.others||[];
  return h("div",{},
    h("div",{class:"row",style:"margin-bottom:12px"}, h("span",{class:"mut",style:"flex:1"},"开关改动需要“保存并应用”；重启按钮立即生效。"),
      h("button",{class:"btn sm",onclick:()=>show("services")},"刷新")),
    h("div",{class:"sys-grid"}, cards),
    h("div",{class:"sys-sp"}),
    ddnsCard(c, dns),
    edgeCard(c, edge, row["mr-edge"]),
    peerTable,
    card("其它服务（由其它页面的配置决定）", others.length ? h("div",{class:"row"}, others.map(x=>h("span",{class:"row",style:"gap:4px;margin-right:10px"},
      h("span",{class:"tag "+(x.running?"ok":"bad")}, x.name), x.installed && x.name!=="mr-network" ? restartBtn(x.name) : null))) : h("span",{class:"mut"},"（无）")));
});

// ---------- 系统设置 ----------
const TZS = [
  ["<+07>-7","曼谷 / 雅加达 / 胡志明市 UTC+7"],["CST-8","北京 / 上海 / 台北 UTC+8"],["HKT-8","香港 UTC+8"],
  ["<+08>-8","新加坡 / 吉隆坡 / 马尼拉 UTC+8"],["JST-9","东京 UTC+9"],["KST-9","首尔 UTC+9"],
  ["IST-5:30","印度 UTC+5:30"],["<+04>-4","迪拜 UTC+4"],["MSK-3","莫斯科 UTC+3"],
  ["EET-2EEST,M3.5.0/3,M10.5.0/4","雅典 / 赫尔辛基 / 基辅"],["CET-1CEST,M3.5.0,M10.5.0/3","柏林 / 巴黎 / 罗马 / 马德里"],
  ["GMT0BST,M3.5.0/1,M10.5.0","伦敦"],["UTC0","UTC"],
  ["EST5EDT,M3.2.0,M11.1.0","纽约 / 多伦多"],["CST6CDT,M3.2.0,M11.1.0","芝加哥"],["MST7MDT,M3.2.0,M11.1.0","丹佛"],
  ["MST7","凤凰城"],["PST8PDT,M3.2.0,M11.1.0","洛杉矶 / 温哥华"],["HST10","夏威夷"],
  ["AEST-10AEDT,M10.1.0,M4.1.0/3","悉尼 / 墨尔本"],["AEST-10","布里斯班"],["NZST-12NZDT,M9.5.0,M4.1.0/3","奥克兰"],
];
function tzPicker(sys){
  const box = h("div");
  let custom = !!sys.timezone && !TZS.some(z=>z[0]===sys.timezone);
  const draw = ()=>{
    const cur = sys.timezone||"";
    const sel = h("select",{onchange:e=>{
      if (e.target.value==="__custom"){ custom=true; }
      else { custom=false; sys.timezone=e.target.value; touch(); }
      draw(); }},
      TZS.map(([v,l])=>h("option",{value:v, selected:!custom && v===cur}, l)),
      h("option",{value:"__custom", selected:custom}, "自定义 POSIX TZ…"));
    if (!custom && !TZS.some(z=>z[0]===cur)) sel.prepend(h("option",{value:cur, selected:true}, cur||"（未设置 = UTC）"));
    box.replaceChildren(sel, custom ? h("div",{style:"margin-top:6px"}, inText(sys,"timezone",{class:"mono", placeholder:"例如 <+07>-7 或 CET-1CEST,M3.5.0,M10.5.0/3"})) : null);
  };
  draw(); return box;
}
registerPage("system", "system", "系统设置", 10, async ()=>{
  const c = C(), s = c.system;
  const clock = h("span",{class:"sys-clock mono"},"…");
  const sync = h("span");
  let base = null;
  const tick = ()=>{
    if (!base) return;
    const t = Date.now()/1000 + base.delta + base.offset;
    clock.textContent = new Date(t*1000).toISOString().replace("T"," ").slice(0,19)+" "+base.zone;
  };
  try {
    const t = await api("sys.time");
    base = {delta: t.now - Date.now()/1000, offset: t.offset||0, zone: (t.local||"").split(" ").slice(2).join(" ")};
    sync.replaceChildren(t.synced===true ? h("span",{class:"tag ok"},"NTP 已同步") : t.synced===false ? h("span",{class:"tag warn"},"NTP 未同步") : h("span",{class:"tag"},"同步状态未知"));
    tick(); S.timer = setInterval(tick, 1000);
  } catch(e){ clock.textContent = tr("读取失败："+e.message); }

  const sys = Object.entries(s.sysctl).map(([k,v])=>({k,v}));
  const syncSys = ()=>{ s.sysctl = Object.fromEntries(sys.filter(x=>x.k).map(x=>[x.k,String(x.v)])); touch(); };
  const st = etable(sys, [{k:"k",l:"参数",ph:"net.ipv4.tcp_congestion_control"},{k:"v",l:"值",ph:"bbr"}], {k:"",v:""}, {noMove:true});
  st.el.addEventListener("input", syncSys); st.el.addEventListener("click", ()=>setTimeout(syncSys));
  st.add.addEventListener("click", ()=>setTimeout(syncSys));
  return h("div",{},
    card("基本设置", form(
      ...field("主机名", inText(s,"hostname",{maxlength:63})),
      ...field("zram 压缩内存", inBool(s,"zram"), "内存的 1/4 做压缩交换（zstd），内存紧张时更稳"))),
    card("时间", form(
      ...field("路由器时间", h("div",{class:"row"}, clock, sync, h("button",{class:"btn sm",onclick:async()=>{
        try { await api("service",{name:"ntpd",op:"restart"}); toast("已重启 ntpd，几秒后同步"); } catch(e){ toast(e.message,4000); } }},"立即同步"))),
      ...field("时区", tzPicker(s), "POSIX TZ 格式（Alpine 不带时区数据库）；写入 /etc/localtime，日志、计划任务都按此时区"),
      ...field("NTP 服务器", inList(s,"ntp",{placeholder:"ntp.tencent.com, ntp1.aliyun.com"}), "域名或 IP，逗号分隔；为空时用 pool.ntp.org"),
      ...field("为局域网提供 NTP", inBool(s,"ntp_server"), "ntpd -l：只有 LAN 区域（含 Tailscale）能访问，访客网络和 WAN 被防火墙挡住。想让设备自动用它，在 DHCP 选项里把 NTP 服务器设为路由器地址。"))),
    card("内核参数 (sysctl)", [h("div",{class:"mut",style:"padding:10px 16px 0"},"覆盖或追加 /etc/sysctl.d/90-mini-router.conf 的值（默认 nf_conntrack_max=100000 等）。"), st.el], st.add, true),
    card("重启", h("div",{class:"row"}, h("span",{class:"mut",style:"flex:1"},"重启路由器，全家断网约 1 分钟。"),
      h("button",{class:"btn d",onclick:async()=>{ if(!confirm("确定重启路由器？")) return; try{ await api("reboot",{}); toast("正在重启…",8000); }catch(e){ toast(e.message,4000); } }},"重启路由器"))));
});

// ---------- 管理与 SSH ----------
const KEY_RE = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+={0,2}( [^\x00-\x1f\x7f]*)?$/;
registerPage("system", "admin", "管理与 SSH", 15, async ()=>{
  const c = C(), ssh = c.services.ssh;
  let k = {managed:[], other:[], root_password:""};
  try { k = await api("sys.sshkeys"); } catch(e){ toast("读取公钥失败："+e.message, 4000); }
  const warn = h("div");
  const keysInfo = h("div",{class:"sys-note"});
  const check = ()=>{
    const lines = ssh.authorized_keys||[];
    const bad = lines.filter(l=>!KEY_RE.test(l));
    keysInfo.replaceChildren(tr(lines.length+" 个受管公钥"), bad.length ? h("span",{class:"err"}, "，"+bad.length+" 行格式不对（保存时会被拒绝）") : "");
    const w = [];
    if (ssh.enabled && !ssh.password_login && !lines.length && !(k.other||[]).length)
      w.push("没有任何公钥且禁止密码登录：SSH 将无法登录（Web 管理不受影响）。");
    if (ssh.enabled && ssh.password_login && k.root_password && k.root_password!=="set")
      w.push("root 没有可用密码（"+(k.root_password==="empty"?"空密码，dropbear 拒绝":"已锁定")+"），密码登录不会成功；用 SSH 登录后执行 passwd 设置。");
    warn.replaceChildren(...w.map(x=>h("div",{class:"sys-warnbox"}, x)));
  };
  const ta = h("textarea",{class:"sys-keys", rows:6, spellcheck:false, placeholder:"每行一个公钥，例如\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… me@laptop",
    oninput:e=>{ ssh.authorized_keys = e.target.value.split("\n").map(x=>x.trim()).filter(x=>x && !x.startsWith("#")); touch(); check(); }},
    (ssh.authorized_keys||[]).join("\n"));
  const onSSH = ()=>check();
  const keyRows = list=>(list||[]).map(x=>[mono(x.type), x.comment||h("span",{class:"mut"},"（无备注）"), mono(x.fingerprint)]);
  const pw = {old:"",nw:"",nw2:""};
  check();
  return h("div",{},
    card("SSH (dropbear)", [form(
      ...field("启用", inBool(ssh,"enabled", onSSH)),
      ...field("端口", inNum(ssh,"port",{min:1,max:65535})),
      ...field("允许密码登录", inBool(ssh,"password_login", onSSH), "建议关闭，只用公钥"),
      ...field("只监听 LAN 地址", inBool(ssh,"lan_only"), "只在 LAN 区域网络的路由器 IPv4 地址上监听（如 192.168.1.6）；访客网络连不上。通过 Tailscale 子网路由访问 LAN 地址仍可用，Tailscale 自己的 100.x 地址和 IPv6 不再监听。")),
      warn]),
    card("SSH 公钥（root）", [
      h("div",{class:"mut",style:"margin-bottom:8px"},"这里的公钥写在 /root/.ssh/authorized_keys 的受管区块里。文件里其它已有的公钥（刷机时装入的、手工加的）mr 从不改动，所以不会把你锁在门外；删除受管公钥只删这里的。"),
      ta, keysInfo,
      h("h4",{style:"margin:14px 0 6px"},"当前生效的受管公钥"),
      roTable(["类型","备注","指纹"], keyRows(k.managed)),
      h("h4",{style:"margin:14px 0 6px"},"其它公钥（mr 不管理）"+(k.other_unparsed?"，另有 "+k.other_unparsed+" 行带选项或无法识别":"")),
      roTable(["类型","备注","指纹"], keyRows(k.other))]),
    card("Web 管理", form(
      ...field("启用 Web 管理", inBool(c.services.panel,"enabled"), h("span",{class:"err"},"关闭后本页面无法访问，只能用 SSH 管理")),
      h("span"), h("div",{class:"mut"},"监听主 LAN 地址的 80 端口；LAN 地址改动后会自动跟随。"))),
    card("管理员密码", form(
      ...field("当前密码", inText(pw,"old",{type:"password",autocomplete:"current-password"})),
      ...field("新密码", inText(pw,"nw",{type:"password",autocomplete:"new-password"}), "至少 8 位；修改后其它已登录的浏览器会被登出"),
      ...field("确认新密码", inText(pw,"nw2",{type:"password",autocomplete:"new-password"})),
      h("span"), h("div",{}, h("button",{class:"btn p",onclick:async()=>{
        if (pw.nw!==pw.nw2) return toast("两次输入不一致");
        if (pw.nw.length<8) return toast("新密码至少 8 位");
        try { await api("password",{old:pw.old,new:pw.nw}); toast("密码已修改"); } catch(e){ toast(e.message,4000); } }},"修改密码")))),
    tokenCard(c));
});

// ---------- API 令牌 (api.tokens; hash in secrets.yaml, see docs/api.md) ----------
const SCOPES = {read:"只读", operate:"操作", apply:"修改配置"};
const tokenKey = n => "api_token_"+n;
function tokenCard(c){
  const toks = ()=>(c.api && c.api.tokens) || [];
  const nt = {name:"", scope:"read", from:[], expires:""};
  const list = h("div");
  let used = {};
  const draw = ()=>list.replaceChildren(toks().length ? roTable(["名称","权限","来源","到期","最后使用",""], toks().map(t=>{
    const u = used[t.name];
    return [mono(t.name), (SCOPES[t.scope]||t.scope)+((t.allow||[]).length ? "（"+t.allow.join(", ")+"）" : ""), (t.from||[]).join(", ")||"任意", h("span",{style:"white-space:nowrap"}, t.expires||"永不"),
      u ? new Date(u.time*1000).toLocaleString()+" · "+u.from : S.secretsSet[tokenKey(t.name)] ? "从未" : h("span",{class:"mut"},"保存并应用后生效"),
      h("button",{class:"btn sm d",onclick:()=>{
        c.api.tokens = toks().filter(x=>x!==t); if (!c.api.tokens.length) delete c.api;
        delete S.secrets[tokenKey(t.name)]; touch(); draw(); }},"吊销")];
  })) : h("div",{class:"mut"},"还没有令牌。"));
  const create = ()=>{
    const name = nt.name.trim();
    if (!/^[a-z][a-z0-9_-]{0,14}$/.test(name)) return toast("名称：小写字母开头，最多 15 个字符（a-z 0-9 _ -）");
    if (toks().some(t=>t.name===name)) return toast("已有同名令牌");
    const tok = "mrt_"+btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
    const sh = new Sha256(); sh.update(new TextEncoder().encode(tok));
    const t = {name, scope:nt.scope};
    if (nt.from.length) t.from = nt.from.slice();
    if (nt.expires) t.expires = nt.expires;
    c.api ||= {}; c.api.tokens ||= []; c.api.tokens.push(t);
    S.secrets[tokenKey(name)] = "sha256:"+sh.hex(); // only the hash leaves the browser
    touch(); draw();
    const m = modal("新令牌 "+name, [h("p",{},"只显示这一次，请现在复制保存（路由器只保存它的哈希）。点“保存并应用”后生效。"),
      h("pre",{style:"user-select:all;white-space:pre-wrap;word-break:break-all"}, tok),
      h("p",{class:"mut"},"curl -H 'Authorization: Bearer mrt_…' 'http://"+location.host+"/cgi-bin/api?a=status'")],
      [navigator.clipboard ? h("button",{class:"btn",onclick:()=>navigator.clipboard.writeText(tok).then(()=>toast("已复制"))},"复制") : null,
       h("button",{class:"btn p",onclick:()=>m.remove()},"我已保存")]);
  };
  api("tokens").then(j=>{ used = j.used||{}; draw(); }).catch(()=>{});
  draw();
  return card("API 令牌（脚本 / Home Assistant / AI agent）", [
    h("div",{class:"mut",style:"margin-bottom:8px"},"请求带 Authorization: Bearer <令牌> 即可调用本页面的 API，不需要登录。只读：状态、配置、监控、变更历史；操作：重拨、踢下线、重启服务、切换代理节点；修改配置：plan / apply / 保留 / 回滚（同样有确认倒计时和自动回滚，历史里记为 api:名称）。任何令牌都不能改管理员密码、读密钥和日志、备份恢复、升级固件、恢复出厂或重启，也不能改令牌、SSH 和 sysctl。"),
    list,
    form(...field("名称", inText(nt,"name",{placeholder:"如 homeassistant", maxlength:15})),
      ...field("权限", inSel(nt,"scope",[["read","只读"],["operate","操作（重拨、踢下线、重启服务）"],["apply","修改配置（plan / apply）"]])),
      ...field("来源", inList(nt,"from",{placeholder:"可选，如 192.168.1.0/24"}), "留空 = 任意来源（管理页只在 LAN 地址上监听）"),
      ...field("到期", inText(nt,"expires",{type:"date"}), "留空 = 永不过期"),
      h("span"), h("div",{}, h("button",{class:"btn p",onclick:create},"生成令牌")))]);
}

// ---------- 计划任务 ----------
const DAYS = [["1","一"],["2","二"],["3","三"],["4","四"],["5","五"],["6","六"],["0","日"]];
const WEEK = ["周日","周一","周二","周三","周四","周五","周六"]; // cron day of week → name
const ACTIONS = {reboot:"重启路由器", restart:"重启服务", reconnect:"重新拨号 / 重连 WAN", wol:"唤醒设备 (WOL)",
  "wifi-off":"关闭 WiFi", "wifi-on":"打开 WiFi", "leds-off":"关闭指示灯", "leds-on":"打开指示灯"};
const pad2 = n=>String(n).padStart(2,"0");
function cronText(spec){
  const f = (spec||"").trim().split(/\s+/);
  if (f.length!==5) return spec||"";
  const [mi,hr,dom,mon,dow] = f;
  const num = x=>/^\d+$/.test(x);
  const at = num(mi)&&num(hr) ? pad2(hr)+":"+pad2(mi) : null;
  if (at && dom==="*" && mon==="*" && dow==="*") return "每天 "+at;
  if (at && dom==="*" && mon==="*" && /^[0-6](,[0-6])*$/.test(dow)) return dow.split(",").map(d=>WEEK[+d]).join("、")+" "+at;
  if (at && dom==="*" && mon==="*" && /^[0-6]-[0-6]$/.test(dow)) return WEEK[+dow[0]]+"至"+WEEK[+dow[2]]+" "+at;
  if (at && num(dom) && mon==="*" && dow==="*") return "每月 "+dom+" 日 "+at;
  if (num(mi) && /^\*\/\d+$/.test(hr) && dom==="*" && mon==="*" && dow==="*") return "每 "+hr.slice(2)+" 小时（第 "+mi+" 分）";
  if (num(mi) && hr==="*" && dom==="*" && mon==="*" && dow==="*") return "每小时第 "+mi+" 分";
  return spec;
}
// cron → editor state {mode, time, days, dom, every, minute, raw}
function cronParse(spec){
  const f = (spec||"").trim().split(/\s+/);
  const st = {mode:"daily", time:"04:00", days:["1"], dom:1, every:6, minute:0, raw:spec||""};
  if (f.length!==5) { if (spec) st.mode="custom"; return st; }
  const [mi,hr,dom,mon,dow] = f, num = x=>/^\d+$/.test(x);
  if (num(mi)&&num(hr)) st.time = pad2(hr)+":"+pad2(mi);
  if (num(mi)) st.minute = +mi;
  if (num(mi)&&num(hr)&&dom==="*"&&mon==="*"&&dow==="*") st.mode="daily";
  else if (num(mi)&&num(hr)&&dom==="*"&&mon==="*"&&/^[0-6](,[0-6])*$/.test(dow)) { st.mode="weekly"; st.days=dow.split(","); }
  else if (num(mi)&&num(hr)&&num(dom)&&mon==="*"&&dow==="*") { st.mode="monthly"; st.dom=+dom; }
  else if (num(mi)&&/^\*\/\d+$/.test(hr)&&dom==="*"&&mon==="*"&&dow==="*") { st.mode="hours"; st.every=+hr.slice(2); }
  else st.mode="custom";
  return st;
}
function cronBuild(st){
  const [H,M] = (st.time||"04:00").split(":").map(x=>+x||0);
  switch (st.mode){
    case "daily": return M+" "+H+" * * *";
    case "weekly": return M+" "+H+" * * "+(st.days.length?DAYS.map(d=>d[0]).filter(d=>st.days.includes(d)).sort().join(","):"*");
    case "monthly": return M+" "+H+" "+(st.dom||1)+" * *";
    case "hours": return (st.minute||0)+" */"+(st.every||1)+" * * *";
  }
  return (st.raw||"").trim();
}
function targetOptions(action, svcNames){
  if (action==="restart") return svcNames.filter(n=>n!=="mr-network").map(n=>[n,n]);
  if (action==="reconnect") return (S.cfg.wan||[]).filter(w=>w.proto!=="static").map(w=>[w.name, w.name+"（"+(w.proto==="pppoe"?"PPPoE 重拨":"DHCP 重新获取")+"）"]);
  if (action==="wol") return (S.cfg.dhcp.hosts||[]).filter(x=>x.name).map(x=>[x.name, x.name+"（"+x.mac+"）"]);
  if (/^wifi-/.test(action)) return [["","全部射频"], ...((S.cfg.wifi||{}).radios||[]).map(r=>[r.phy, r.phy+"（"+r.band+"）"])];
  return [];
}
function editSchedule(orig, svcNames, onSave){
  const x = clone(orig);
  x.action ||= "reboot";
  const st = cronParse(x.cron);
  const timeBox = h("div"), chk = h("div",{class:"sys-note"}), tgt = h("div");
  let seq = 0;
  const verify = async ()=>{
    x.cron = cronBuild(st);
    const my = ++seq;
    chk.replaceChildren(h("span",{class:"mono"}, x.cron||"（空）"), "  ", tr(cronText(x.cron)));
    try {
      const r = await api("sys.schedulecheck",{cron:x.cron, action:x.action});
      if (my!==seq) return;
      chk.append("  ", r.ok ? h("span",{class:"tag ok"},"格式正确") : h("span",{class:"err"}, r.error));
    } catch(e){}
  };
  const drawTarget = ()=>{
    const opts = targetOptions(x.action, svcNames);
    if (!opts.length){ delete x.target; tgt.replaceChildren(h("span",{class:"mut"}, x.action==="reboot"||/^leds/.test(x.action)?"—":"（没有可选项）")); return; }
    if (!opts.some(o=>o[0]===(x.target||""))) x.target = opts[0][0];
    tgt.replaceChildren(inSel(x,"target",opts));
  };
  const drawTime = ()=>{
    const modes = [["daily","每天"],["weekly","每周"],["monthly","每月"]];
    if (x.action!=="reboot") modes.push(["hours","每 N 小时"]);
    modes.push(["custom","自定义 cron"]);
    if (x.action==="reboot" && st.mode==="hours") st.mode="daily";
    const timeIn = ()=>h("input",{type:"time", value:st.time, style:"max-width:130px", oninput:e=>{ st.time=e.target.value||"00:00"; verify(); }});
    const parts = [inSel(st,"mode",modes,()=>{ if (st.mode==="custom" && !st.raw) st.raw = x.cron; drawTime(); verify(); })];
    if (st.mode==="daily") parts.push(timeIn());
    if (st.mode==="weekly"){
      const box = h("span",{class:"sys-days"});
      const drawDays = ()=>box.replaceChildren(...DAYS.map(([v,l])=>h("label",{class:st.days.includes(v)?"on":""},
        h("input",{type:"checkbox", checked:st.days.includes(v), onchange:e=>{ st.days = e.target.checked ? [...st.days, v] : st.days.filter(d=>d!==v); drawDays(); verify(); }}), l)));
      drawDays(); parts.push(box, timeIn());
    }
    if (st.mode==="monthly") parts.push(h("span",{class:"row"}, "第", h("input",{type:"number",min:1,max:31,value:st.dom,style:"width:70px",oninput:e=>{ st.dom=+e.target.value||1; verify(); }}), "号"), timeIn());
    if (st.mode==="hours") parts.push(h("span",{class:"row"}, "每", h("input",{type:"number",min:1,max:23,value:st.every,style:"width:70px",oninput:e=>{ st.every=+e.target.value||1; verify(); }}), "小时，第",
      h("input",{type:"number",min:0,max:59,value:st.minute,style:"width:70px",oninput:e=>{ st.minute=+e.target.value||0; verify(); }}), "分钟"));
    if (st.mode==="custom") parts.push(h("input",{type:"text", class:"mono", value:st.raw, placeholder:"分 时 日 月 周，例如 30 4 * * 1",
      oninput:e=>{ st.raw=e.target.value; verify(); }}),
      h("div",{class:"sys-note"},"只能用数字、*、a-b、*/n 和逗号；分钟必须是一个固定数字（每小时最多一次），重启路由器的小时也必须固定（每天最多一次）。周：0=周日 … 6=周六。"));
    timeBox.replaceChildren(h("div",{style:"display:grid;gap:8px"}, parts));
  };
  drawTarget(); drawTime(); verify();
  const m = modal(orig.name ? "编辑计划任务" : "添加计划任务", form(
    ...field("名称", inText(x,"name",{placeholder:"weekly-reboot", maxlength:40}), "字母、数字、_ . -"),
    ...field("启用", h("label",{class:"sw"}, h("input",{type:"checkbox", checked:x.enabled!==false, onchange:e=>{ if (e.target.checked) delete x.enabled; else x.enabled=false; }}), h("span"))),
    ...field("动作", inSel(x,"action",Object.entries(ACTIONS),()=>{ drawTarget(); drawTime(); verify(); })),
    ...field("对象", tgt),
    ...field("时间", timeBox),
    h("span"), chk),
    [h("button",{class:"btn",onclick:()=>m.remove()},"取消"), h("button",{class:"btn p",onclick:()=>{
      x.cron = cronBuild(st);
      if (!/^[A-Za-z0-9_.-]{1,40}$/.test(x.name||"")) return toast("名称：字母、数字、_ . -，1-40 个字符", 4000);
      if (!x.target) delete x.target;
      m.remove(); onSave(x); }},"确定")]);
}
registerPage("system", "schedules", "计划任务", 20, async ()=>{
  const c = C(), list = c.schedules;
  let svcNames = [];
  try { const d = await api("sys.services"); svcNames = [...(d.services||[]).filter(s=>s.wanted).map(s=>s.name), ...(d.others||[]).map(s=>s.name)]; } catch(e){}
  const tb = h("tbody");
  const draw = ()=>{
    tb.replaceChildren();
    if (!list.length) tb.append(h("tr",{}, h("td",{colspan:6, class:"mut"},"（没有计划任务）")));
    list.forEach((x,i)=>{
      const on = x.enabled!==false;
      tb.append(h("tr",{class:on?"":"sys-off"},
        h("td",{class:"sys-keep",style:"width:1%"}, h("label",{class:"sw"}, h("input",{type:"checkbox", checked:on, onchange:e=>{ if (e.target.checked) delete x.enabled; else x.enabled=false; touch(); draw(); }}), h("span"))),
        h("td",{}, h("b",{}, x.name)),
        h("td",{}, cronText(x.cron), h("div",{class:"mut mono"}, x.cron)),
        h("td",{}, ACTIONS[x.action]||x.action),
        h("td",{}, x.target ? mono(x.target) : dash("")),
        h("td",{class:"sys-keep",style:"width:1%;white-space:nowrap"},
          h("button",{class:"btn sm",onclick:()=>editSchedule(x, svcNames, y=>{ list[i]=y; touch(); draw(); })},"编辑"), " ",
          h("button",{class:"btn sm d",onclick:()=>{ list.splice(i,1); touch(); draw(); }},"删除"))));
    });
  };
  draw();
  const add = h("button",{class:"btn sm p",onclick:()=>editSchedule({name:"", action:"reboot", cron:"30 4 * * 1"}, svcNames, y=>{ list.push(y); touch(); draw(); })},"+ 添加");
  return h("div",{},
    card("计划任务", [h("div",{class:"mut",style:"padding:10px 16px"},
      "由 busybox crond 按路由器时区执行，只有固定的几种动作：重启路由器、重启某个服务、重连某条 WAN（PPPoE 重拨 / DHCP 重新获取）、唤醒设备（WOL，对象是 DHCP 静态分配里的主机）、关闭 / 打开 WiFi 和指示灯。每次执行都记入系统日志和“最近变更”。"
      +"关闭 / 打开是时间段：重启、应用配置或 hostapd 重启后按最近一次触发的动作恢复（例如 23:00 关、7:00 开，半夜重启后 WiFi 仍是关的）。"),
      h("div",{class:"tw"}, h("table",{}, h("thead",{}, h("tr",{}, ["启用","名称","时间","动作","对象",""].map(x=>h("th",{},x)))), tb))], add, true));
});

// ---------- 备份与升级 ----------
// ---- sha256 begin (streaming SHA-256; crypto.subtle is missing on plain-http pages)
const SHA_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
function Sha256(){ this.h=new Int32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]); this.w=new Int32Array(64); this.buf=new Uint8Array(64); this.n=0; this.len=0; }
Sha256.prototype.block = function(b, o){
  const w=this.w, hs=this.h;
  for (let i=0;i<16;i++) w[i]=(b[o+4*i]<<24)|(b[o+4*i+1]<<16)|(b[o+4*i+2]<<8)|b[o+4*i+3];
  for (let i=16;i<64;i++){ const x=w[i-15], y=w[i-2];
    w[i]=(w[i-16]+(((x>>>7)|(x<<25))^((x>>>18)|(x<<14))^(x>>>3))+w[i-7]+(((y>>>17)|(y<<15))^((y>>>19)|(y<<13))^(y>>>10)))|0; }
  let a=hs[0],bb=hs[1],c=hs[2],d=hs[3],e=hs[4],f=hs[5],g=hs[6],hh=hs[7];
  for (let i=0;i<64;i++){
    const t1=(hh+(((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7)))+((e&f)^(~e&g))+SHA_K[i]+w[i])|0;
    const t2=((((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10)))+((a&bb)^(a&c)^(bb&c)))|0;
    hh=g; g=f; f=e; e=(d+t1)|0; d=c; c=bb; bb=a; a=(t1+t2)|0;
  }
  hs[0]+=a; hs[1]+=bb; hs[2]+=c; hs[3]+=d; hs[4]+=e; hs[5]+=f; hs[6]+=g; hs[7]+=hh;
};
Sha256.prototype.update = function(d){
  let i=0; this.len+=d.length;
  if (this.n){ while (this.n<64 && i<d.length) this.buf[this.n++]=d[i++]; if (this.n<64) return; this.block(this.buf,0); this.n=0; }
  for (; i+64<=d.length; i+=64) this.block(d,i);
  while (i<d.length) this.buf[this.n++]=d[i++];
};
Sha256.prototype.hex = function(){
  const bits=this.len*8, hi=Math.floor(bits/4294967296), lo=bits>>>0;
  const pad=new Uint8Array((this.n<56?56:120)-this.n+8), L=pad.length; pad[0]=0x80;
  pad[L-8]=hi>>>24; pad[L-7]=hi>>>16; pad[L-6]=hi>>>8; pad[L-5]=hi; pad[L-4]=lo>>>24; pad[L-3]=lo>>>16; pad[L-2]=lo>>>8; pad[L-1]=lo;
  this.update(pad);
  return Array.from(this.h, x=>(x>>>0).toString(16).padStart(8,"0")).join("");
};
// ---- sha256 end
async function fileSHA256(file, onProgress){
  if (window.crypto && crypto.subtle && file.size <= 256*1024*1024){
    try { const d = await crypto.subtle.digest("SHA-256", await file.arrayBuffer()); onProgress(1);
      return Array.from(new Uint8Array(d), b=>b.toString(16).padStart(2,"0")).join(""); } catch(e){}
  }
  const s = new Sha256(), step = 4<<20;
  for (let off=0; off<file.size; off+=step){ s.update(new Uint8Array(await file.slice(off, off+step).arrayBuffer())); onProgress(Math.min(1,(off+step)/file.size)); await sleep(0); }
  return s.hex();
}
function progress(){ const i=h("i"); const el=h("div",{class:"sys-prog"}, i); el.set=f=>{ i.style.width=(Math.max(0,Math.min(1,f))*100).toFixed(1)+"%"; }; return el; }

// the standard apply progress (validate → apply job → confirm / automatic rollback), for a restore
function watchApply(title){
  const log = h("pre",{},""), stateEl = h("div",{style:"margin-bottom:8px"},"正在应用…"), foot = h("div",{class:"row"});
  const m = modal(title, [stateEl, log], [foot]);
  let seenOk = 0, fails = 0;
  const finish = ()=>{ m.remove(); location.reload(); };
  const poll = async ()=>{
    let j;
    try { j = await api("job"); fails = 0; } catch(e){ if (!S.auth) { m.remove(); return; } fails++; stateEl.textContent = tr("暂时连不上路由器（"+fails+"）… 如果备份里的 LAN 地址不同，请到新地址访问；超时未确认会自动回滚。"); return setTimeout(poll, 2000); }
    const job = j.job||{}; log.textContent = job.output||"";
    if (job.state==="running") return setTimeout(poll, 1200);
    if (job.state==="failed"){
      stateEl.replaceChildren(h("b",{class:"err"},"应用失败，已自动回滚（列表文件也已放回）。"));
      foot.replaceChildren(h("button",{class:"btn p",onclick:finish},"关闭"));
      return;
    }
    if (!j.confirm_pending){
      stateEl.replaceChildren(h("b",{style:"color:var(--ok)"},"已恢复并保留。"));
      foot.replaceChildren(h("button",{class:"btn p",onclick:finish},"完成"));
      return;
    }
    if (!seenOk){
      seenOk = Date.now();
      const left = h("span");
      const tick = setInterval(()=>{ const s=Math.max(0,(job.confirm||120)-Math.floor((Date.now()-seenOk)/1000)); left.textContent=tr(s+" 秒后自动回滚"); if(!s) clearInterval(tick); }, 500);
      stateEl.replaceChildren(h("b",{style:"color:var(--ok)"},"已应用。"), " 网络正常的话请点“保留”，否则 ", left, "。");
      foot.replaceChildren(
        h("button",{class:"btn d",onclick:async()=>{ clearInterval(tick); await api("revert",{}).catch(()=>{}); m.remove(); toast("正在回滚…",4000); setTimeout(()=>location.reload(), 5000); }},"立即回滚"),
        h("button",{class:"btn p",onclick:async()=>{ clearInterval(tick); try { await api("confirm",{}); } catch(e){} toast("已保留"); finish(); }},"保留"));
    }
  };
  poll();
}

// 异地备份 (notify.archive, docs/modules/sys.md): type -> [label, [key, label, hint]…]; *_secret keys get a name + value row
const ARCH = {
  webdav:["WebDAV", [["url","文件夹地址","https://，例如坚果云 https://dav.jianguoyun.com/dav/备份/（密码用坚果云的“应用密码”）"],
    ["user","账号"], ["password_secret","密码","archive_dav_password"], ["name","文件名","留空 = 每次一个 router-日期-时间.yaml"]]],
  s3:["S3 兼容", [["url","Endpoint","https://，例如 R2 https://账号ID.r2.cloudflarestorage.com；阿里云 OSS 填 https://桶名.oss-cn-hangzhou.aliyuncs.com 并留空桶名"],
    ["region","区域","R2 填 auto"], ["bucket","桶名","留空 = Endpoint 已含桶名"], ["prefix","前缀","例如 backups/"],
    ["access_key_id","Access Key ID"], ["secret_key_secret","Secret Access Key","archive_s3_key"], ["name","文件名","留空 = 每次一个 router-日期-时间.yaml"]]],
  github:["GitHub", [["repo","仓库","owner/name，建议私有仓库"], ["branch","分支","留空 = 默认分支"], ["path","文件路径","默认 router.yaml"],
    ["token_secret","Token","archive_github_token"]]],
  https:["自定义网址", [["url_secret","URL","archive_url"], ["token_secret","Bearer Token（可选）","archive_token"]]],
};
async function archiveCard(){
  const c = C(), box = h("div"), last = h("div",{class:"sys-note"});
  const show = r=>last.replaceChildren(!r || !r.time ? tr("还没有备份过。") : r.ok ? h("span",{style:"color:var(--ok)"}, tr("上次备份成功："+new Date(r.time*1000).toLocaleString())) :
    h("span",{class:"err"}, tr("上次备份失败（"+new Date(r.time*1000).toLocaleString()+"）："), r.error));
  api("sys.archivetest").then(show).catch(()=>{});
  const attach = a=>{ c.notify ||= {}; c.notify.archive = a; touch(); };
  const setType = (a, t)=>{ for (const k of Object.keys(a)) delete a[k]; a.type = t;
    for (const [k,,d] of ARCH[t][1]) if (k.endsWith("_secret") && !(t==="https" && k==="token_secret")) a[k] = d;
    if (t==="s3") a.region = "auto"; };
  const draw = ()=>{
    const a = c.notify && c.notify.archive;
    if (!a) return box.replaceChildren(form(...field("开启", inBool({on:false},"on",()=>{ const n = {}; setType(n,"webdav"); attach(n); draw(); }),
      "每次确认的配置更改后，把 router.yaml（不含机密）传到异地")));
    const t = ARCH[a.type||"https"] ? a.type||"https" : "https";
    const rows = [...field("开启", inBool({on:true},"on",()=>{ delete c.notify.archive; touch(); draw(); })),
      ...field("类型", inSel({type:t},"type",Object.entries(ARCH).map(([k,v])=>[k,v[0]]), v=>{ setType(a,v); touch(); draw(); }))];
    for (const [k,l,hint] of ARCH[t][1]){
      if (k.endsWith("_secret")) rows.push(...field(l+" 引用名", inText(a,k,{class:"mono",placeholder:hint}), "secrets.yaml 里的名字"), ...field(l, inSecret(a,k), "只写入 secrets.yaml，页面不会显示"));
      else rows.push(...field(l, inText(a,k,{class:"mono"}), hint));
    }
    if (t==="https") rows.push(...field("方法", inSel(a,"method",[["post","POST"],["put","PUT"]])));
    box.replaceChildren(form(...rows));
  };
  draw();
  const test = h("button",{class:"btn sm",onclick:async()=>{
    test.disabled = true;
    try { show(await api("sys.archivetest",{})); } catch(e){ toast(e.message, 5000); }
    test.disabled = false; }},"立即备份测试");
  return card("异地备份", [box, last, h("div",{class:"sys-note"},"WebDAV（坚果云、Nextcloud、NAS）、S3 兼容（Cloudflare R2、阿里云 OSS、MinIO、Backblaze B2）、GitHub 仓库或自定义 https 地址。",
    "密钥只存在路由器的 secrets.yaml 里。“立即备份测试”用已应用的配置。")], test);
}

registerPage("system", "backup", "备份与升级", 35, async ()=>{
  let fw = {};
  try { fw = await api("sys.fw"); } catch(e){ fw = {error:e.message}; }
  // --- backup
  const bo = {secrets:false};
  const bInfo = h("div",{class:"sys-note"});
  const backupCard = card("备份配置", [form(
    ...field("包含机密", inBool(bo,"secrets"), "PPPoE / WiFi / 代理等密码（secrets.yaml，明文）；不含 Web 管理员密码。只在需要换机或重刷时勾选，并妥善保管文件。"),
    h("span"), h("div",{}, h("button",{class:"btn p",onclick:async e=>{
      e.target.disabled = true;
      try {
        const r = await api("sys.backup",{secrets:bo.secrets});
        download(r.name, unb64(r.data), "application/gzip");
        bInfo.replaceChildren(tr("已下载 "+r.name+"（"+fmtBytes(r.size)+"）："), h("span",{class:"mono"}, (r.files||[]).join("  ")),
          r.restorable===false ? h("div",{class:"err"},"文件超过恢复上传上限（"+fmtBytes(r.max_upload)+"），恢复时需要用 SSH：mr sys restore") : null);
      } catch(x){ toast(x.message,4000); }
      e.target.disabled = false; }},"下载备份"), bInfo)),
    h("div",{class:"sys-note"},"内容：router.yaml、（可选）secrets.yaml、/etc/mini-router/dns 与 /etc/mini-router/proxy 下的列表文件。")]);

  // --- restore
  const rFile = h("input",{type:"file", accept:".tar.gz,.tgz,application/gzip"});
  const rErr = h("div");
  const restoreCard = card("恢复配置", [
    h("div",{class:"mut",style:"margin-bottom:10px"},"上传备份文件后先校验（只接受 router.yaml、secrets.yaml 和 dns/proxy 列表文件），再按正常流程应用：先存快照，应用后 120 秒内确认，否则自动回滚。备份里没有机密时沿用当前的机密；管理员密码不变。"),
    h("div",{class:"sys-file"}, rFile, h("button",{class:"btn p",onclick:async e=>{
      rErr.replaceChildren();
      const f = rFile.files[0];
      if (!f) return toast("先选择备份文件");
      if (f.size > 2900000) return toast("文件太大（上限约 2.9 MB）；请用 SSH：mr sys restore 文件", 5000);
      if (!confirm("用 "+f.name+" 覆盖当前配置？应用后需在 120 秒内确认。")) return;
      e.target.disabled = true;
      try {
        await api("sys.restore",{data:b64(new Uint8Array(await f.arrayBuffer())), confirm:120});
        watchApply("恢复配置");
      } catch(x){
        rErr.replaceChildren(h("div",{class:"sys-errbox"}, "未恢复："+(x.data&&x.data.error?x.data.error:x.message)+(x.data&&x.data.errors?"\n"+x.data.errors.join("\n"):"")));
      }
      e.target.disabled = false; }},"校验并恢复")), rErr]);

  // --- firmware
  const unsupported = msg=>h("div",{class:"sys-warnbox"}, msg);
  let fwBody;
  if (fw.error) fwBody = h("div",{class:"err"}, fw.error);
  else if (!fw.sysupgrade) fwBody = unsupported("当前构建不支持在线升级（缺少 /usr/libexec/mr/sysupgrade）。");
  else {
    const fFile = h("input",{type:"file"});
    const status = h("div"), bar = progress();
    const run = fw.run||{};
    if (run.state==="failed") status.append(h("div",{class:"sys-errbox"}, "上次升级被拒绝（退出码 "+run.rc+"）：\n"+(run.message||"")));
    const up = fw.upload;
    const cancelBtn = h("button",{class:"btn sm",onclick:async()=>{ try { await api("sys.fwupload",{cancel:true}); toast("已删除上传的镜像"); show("backup"); } catch(e){ toast(e.message,4000); } }},"删除已上传的镜像");
    const go = h("button",{class:"btn p",onclick:async()=>{
      const f = fFile.files[0];
      if (!f) return toast("先选择固件文件");
      if (f.size > (fw.max_image||134217728)) return toast("文件太大（上限 "+fmtBytes(fw.max_image)+"）", 4000);
      if (fw.tmp_free && f.size + (8<<20) > fw.tmp_free) return toast("/tmp 空间不足（剩余 "+fmtBytes(fw.tmp_free)+"）", 4000);
      go.disabled = true; fFile.disabled = true; status.replaceChildren();
      try {
        status.replaceChildren(tr("计算 SHA-256…"), bar); bar.set(0);
        const sum = await fileSHA256(f, p=>bar.set(p));
        const chunk = Math.min(fw.max_chunk||(2<<20), 1<<20);
        let off = 0, retry = 0;
        status.replaceChildren(tr("上传中… "), h("span",{class:"mono"}, "SHA-256 "+sum), bar);
        while (off < f.size){
          const part = new Uint8Array(await f.slice(off, off+chunk).arrayBuffer());
          try {
            const r = await api("sys.fwupload",{offset:off, total:f.size, data:b64(part)});
            off = (typeof r.received==="number" && r.received>off) ? r.received : off+part.length; retry = 0;
          } catch(e){
            if (e.data && typeof e.data.received==="number" && retry<3){ off = e.data.received; retry++; continue; }
            if (!e.data && retry<5){ retry++; await sleep(1500); continue; }
            throw e;
          }
          bar.set(off/f.size);
        }
        if (!confirm("镜像已上传并校验（"+fmtBytes(f.size)+"，SHA-256 "+sum.slice(0,16)+"…）。\n开始刷写？升级期间请勿断电，完成后路由器自动重启，全家断网几分钟。")){
          status.replaceChildren(tr("已上传，未刷写。"), cancelBtn); go.disabled=false; fFile.disabled=false; return;
        }
        await api("sys.fwupgrade",{sha256:sum});
        status.replaceChildren(h("b",{},"正在升级，请勿断电…"), h("div",{class:"sys-note"},"路由器会自行重启；重启完成后本页会回到登录界面。"));
        const t0 = Date.now();
        while (Date.now()-t0 < 15*60*1000){
          await sleep(3000);
          let s;
          if (S.page!=="backup") return; // navigated away: stop polling
          try { s = await api("sys.fw"); } catch(e){
            if (!S.auth) return; // rebooted: the session is gone and the login page is showing
            status.replaceChildren(h("b",{},"路由器正在重启…"), h("div",{class:"sys-note"},"稍后刷新页面并重新登录。")); continue; }
          const r = s.run||{};
          if (r.state==="failed"){ status.replaceChildren(h("div",{class:"sys-errbox"}, "升级被拒绝（退出码 "+r.rc+"）：\n"+(r.message||""))); break; }
          if (r.state==="done"){ status.replaceChildren(h("b",{},"刷写完成，等待重启…")); }
        }
      } catch(e){ status.append(h("div",{class:"sys-errbox"}, "失败："+errText(e))); }
      go.disabled = false; fFile.disabled = false;
    }},"上传并升级");
    fwBody = [h("div",{class:"mut",style:"margin-bottom:10px"},"选择固件镜像：先在浏览器里算 SHA-256，分块上传到路由器 /tmp，校验一致后交给平台升级脚本（它会检查镜像、刷写并重启）。建议升级前先下载一份备份。"),
      h("div",{class:"sys-file"}, fFile, go), status,
      up ? h("div",{class:"sys-note"}, "/tmp 里有上次上传的镜像（"+fmtBytes(up.received)+" / "+fmtBytes(up.total)+"）。 ", cancelBtn) : null,
      h("div",{class:"sys-note"}, "/tmp 可用 "+fmtBytes(fw.tmp_free||0)+"，镜像上限 "+fmtBytes(fw.max_image||0)+"。")];
  }

  // --- factory reset
  let resetBody;
  if (fw.error) resetBody = h("span",{class:"mut"},"—");
  else if (!fw.factory_reset) resetBody = unsupported("当前构建不支持恢复出厂设置（缺少 /usr/libexec/mr/factory-reset）。");
  else resetBody = h("div",{class:"row"}, h("span",{class:"mut",style:"flex:1"},"清除全部配置（含 WiFi、PPPoE 密码、端口转发）并重启，之后只能通过网线在默认地址重新设置。"),
    h("button",{class:"btn d",onclick:()=>{
      if (!confirm("恢复出厂设置会清除全部配置并重启路由器。继续？")) return;
      const inp = h("input",{type:"text", placeholder:"RESET", autocomplete:"off"});
      const m = modal("再次确认：恢复出厂设置", [h("p",{},"全家会断网，所有设置丢失。确定的话请输入 ", h("b",{class:"mono"},"RESET"), "："), inp],
        [h("button",{class:"btn",onclick:()=>m.remove()},"取消"), h("button",{class:"btn d",onclick:async()=>{
          if (inp.value!=="RESET") return toast("请输入 RESET");
          try { await api("sys.factoryreset",{confirm:"RESET"}); m.remove(); toast("正在恢复出厂设置，路由器将重启…", 10000); } catch(e){ toast(e.message,5000); } }},"恢复出厂设置")]);
      inp.focus(); }},"恢复出厂设置…"));

  return h("div",{}, backupCard, await archiveCard(), restoreCard, card("固件升级", fwBody), card("恢复出厂设置", resetBody),
    h("div",{class:"mut"},"每次应用配置前的自动快照在 ", h("a",{href:"#history"},"备份与回滚"), " 页面。"));
});

// ---------- 日志 ----------
const LEVELS = [["7","全部级别"],["6","信息及以上"],["5","通知及以上"],["4","警告及以上"],["3","错误及以上"]];
const LVNAME = ["emerg","alert","crit","err","warn","notice","info","debug"];
const logFilter = {level:"7", tag:"", q:"", limit:"500", auto:false}; // kept while the UI is open
registerPage("system", "logs", "日志", 40, ()=>{
  const f = logFilter;
  const out = h("div",{class:"sys-log"}, h("div",{class:"t"},"加载中…"));
  const info = h("span",{class:"mut"});
  const tagBox = h("span");
  let tags = {}, qTimer = null;
  const drawTags = ()=>{
    const opts = [["","全部服务"], ...Object.entries(tags).sort((a,b)=>b[1]-a[1]).map(([t,n])=>[t, t+" ("+n+")"])];
    if (f.tag && !tags[f.tag]) opts.push([f.tag, f.tag]);
    tagBox.replaceChildren(inSel(f,"tag",opts,()=>load()));
  };
  const load = async ()=>{
    let j;
    try { j = await api("sys.logs",{level:+f.level, tag:f.tag, q:f.q, limit:+f.limit}); } catch(e){ out.replaceChildren(h("div",{class:"err"}, e.message)); return; }
    tags = j.tags||{}; drawTags();
    info.textContent = tr("显示 "+(j.lines||[]).length+" / 共 "+j.total+" 行（新的在上）");
    out.replaceChildren(...(j.lines||[]).map(([t,lv,fac,tag,msg])=>h("div",{class:lv>=0?"l"+lv:""},
      t?h("span",{class:"t"}, t+" "):null, lv>=0?h("span",{title:fac}, LVNAME[lv]+" "):null, tag?h("span",{class:"g"}, tag+": "):null, msg)));
    if (!(j.lines||[]).length) out.append(h("div",{class:"t"},"（没有匹配的日志）"));
  };
  const q = h("input",{type:"text", placeholder:"关键字", value:f.q, oninput:e=>{ f.q=e.target.value; clearTimeout(qTimer); qTimer=setTimeout(load, 400); }});
  const auto = ()=>{ clearInterval(S.timer); S.timer = f.auto ? setInterval(()=>load(), 5000) : null; };
  drawTags(); load(); auto();
  return card("系统日志", [
    h("div",{class:"sys-filters"}, inSel(f,"level",LEVELS,()=>load()), tagBox, q,
      inSel(f,"limit",[["300","300 行"],["500","500 行"],["2000","2000 行"],["5000","5000 行"]],()=>load()),
      h("span",{class:"row",style:"gap:4px"}, inBool(f,"auto",()=>auto()), "自动刷新"),
      h("button",{class:"btn sm",onclick:()=>load()},"刷新")),
    h("div",{style:"margin-bottom:6px"}, info), out,
    h("div",{class:"sys-note"},"来源：/var/log/messages（busybox syslogd，时间为路由器时区）。内核日志在 状态 → 进程与内核日志。")]);
});

// ---------- 网络诊断 ----------
const diagForm = {tool:"ping", host:"1.1.1.1"};
registerPage("system", "diag", "网络诊断", 50, ()=>{
  const o = diagForm;
  const out = h("pre",{style:"min-height:120px"}, "");
  const cmd = h("div",{class:"sys-note mono"});
  const btn = h("button",{class:"btn p",onclick:async()=>{
    btn.disabled = true; out.textContent = tr("运行中…（最长 25 秒）"); cmd.textContent = "";
    try { const r = await api("diag",o); out.textContent = r.output || tr("(无输出)"); cmd.textContent = r.command ? "$ "+r.command : ""; } catch(e){ out.textContent = e.message; }
    btn.disabled = false; }},"开始");
  const presets = h("div",{class:"row"}, [["1.1.1.1","ping"],["223.5.5.5","ping"],["2606:4700:4700::1111","ping6"],["www.qq.com","nslookup"]].map(([host,tool])=>
    h("button",{class:"btn sm",onclick:()=>{ o.host=host; o.tool=tool; show("diag"); }}, tool+" "+host)));
  const sp = h("span",{class:"mono"});
  const sbtn = h("button",{class:"btn",onclick:async()=>{
    sbtn.disabled = true; sp.textContent = tr("测速中…（约 20 秒）");
    try { const r = await api("sys.speedtest",{}); sp.textContent = "↓ "+r.down_mbps+" / ↑ "+r.up_mbps+" Mbit/s"; } catch(e){ sp.textContent = e.message; }
    sbtn.disabled = false; }},"测速");
  return h("div",{}, card("网络诊断", [form(
    ...field("工具", inSel(o,"tool",[["ping","Ping (IPv4)"],["ping6","Ping (IPv6)"],["traceroute","Traceroute (IPv4)"],["traceroute6","Traceroute (IPv6)"],["nslookup","DNS 查询 (nslookup，经本机 dnsmasq)"]])),
    ...field("目标", inText(o,"host",{placeholder:"域名或 IP", onkeydown:e=>{ if (e.key==="Enter") btn.click(); }})),
    h("span"), h("div",{class:"row"}, btn),
    h("span"), presets),
    h("div",{style:"margin-top:14px"}, cmd, out)]),
    card("测速 (Cloudflare)", [h("div",{class:"row"}, sbtn, sp), h("div",{class:"sys-note"},"路由器经默认线路下载、上传各约 8 秒（单连接），结果是下限。")]));
});

// ---------- 体检与事件: mr doctor, the event log, notifications (router.yaml notify) ----------
const EVT = {wan_down:"WAN 断线", wan_up:"WAN 恢复", failover:"线路切换", apply:"配置更改", rollback:"回滚",
  login_lock:"登录锁定", new_device:"新设备", boot:"开机", upgrade:"固件升级", doctor:"体检", cert:"证书", wifi:"WiFi 自愈", ddns:"DDNS",
  update:"新版本", archive:"异地归档", watchcat:"断网自救", device:"设备上下线", dial:"拨号顺序"};
const EVT_ALL = Object.keys(EVT);
const SEV = {risk:["风险","bad"], warn:["警告","warn"], ok:["正常","ok"], skip:["跳过",""], info:["信息",""]};
const sevTag = s=>{ const m = SEV[s]||[s,""]; return h("span",{class:"tag "+m[1], style:"white-space:nowrap"}, m[0]); };
const CHECKS = {config:"配置", pending:"待确认更改", wan:"WAN", routes:"路由", dns:"DNS", ipv6:"IPv6", offload:"流量加速",
  services:"服务", wifi:"无线", clock:"时间", storage:"存储", memory:"内存", conntrack:"连接数", temp:"温度", crash:"内核", ssh:"SSH",
  upgrade:"新固件", dnsguard:"DNS 绕过"};
const when = t => t ? new Date(t*1000).toLocaleString() : "—";
const stamp = t=>{ const d = new Date(t*1000), p = n=>String(n).padStart(2,"0");
  return d.getFullYear()+"-"+p(d.getMonth()+1)+"-"+p(d.getDate())+" "+p(d.getHours())+":"+p(d.getMinutes())+":"+p(d.getSeconds()); };

async function pageDoctor(){
  const box = h("div");
  const again = h("button",{class:"btn sm"},"重新体检");
  const run = async ()=>{
    again.disabled = true;
    box.replaceChildren(h("div",{class:"mut",style:"padding:10px 16px"},"正在体检…（几秒）"));
    try {
      const r = await api("sys.doctor");
      const rank = {risk:0, warn:1, ok:2, skip:3};
      const fs = (r.checks||[]).slice().sort((a,b)=>(rank[a.sev]??4)-(rank[b.sev]??4));
      box.replaceChildren(
        h("div",{class:"row",style:"padding:10px 16px"}, sevTag("risk"), " "+r.risk, sevTag("warn"), " "+r.warn, sevTag("ok"), " "+r.ok,
          h("span",{class:"mut",style:"flex:1;text-align:right"}, when(r.time))),
        ...fs.map(f=>h("div",{class:"sys-ev"},
          h("div",{class:"row"}, sevTag(f.sev), h("b",{}, CHECKS[f.check]||f.check), f.id!==f.check ? h("span",{class:"mut mono"}, f.id) : null),
          h("div",{class:"m"}, h("b",{}, f.title), " ", f.detail),
          f.fix && f.sev!=="ok" && f.sev!=="skip" ? h("div",{class:"m mono sys-fix"}, "→ "+f.fix) : null)));
    } catch(e){ box.replaceChildren(h("div",{class:"err",style:"padding:10px 16px"}, e.message)); }
    again.disabled = false;
  };
  again.onclick = run;
  run();
  const heal = h("button",{class:"btn sm",title:"重启已启用但没在运行的服务（每个服务 10 分钟内最多一次）",onclick:async()=>{
    heal.disabled = true;
    try {
      const r = await api("sys.heal",{});
      toast((r.actions||[]).length ? r.actions.join("；") : "没有需要修复的服务", 6000);
      run();
    } catch(e){ toast(e.message, 5000); }
    heal.disabled = false; }},"一键修复");
  return h("div",{},
    card("体检（mr doctor）", box, h("span",{class:"row"}, heal, again), true),
    h("div",{class:"sys-note"}, "只读检查：配置与 guard、待确认的更改、WAN / 路由 / DNS / IPv6、流量加速、服务、无线、时间、存储、内存、连接数、温度、内核崩溃、SSH。",
      "“通知”里设了体检间隔时，后台定期体检，新出现或变严重的问题记为事件并推送。命令行：mr doctor。"));
}

const evFilter = {type:""};
async function pageEvents(){
  const j = await api("sys.events");
  const box = h("div");
  const draw = ()=>{
    const rows = (j.events||[]).filter(e=>!evFilter.type || e.type===evFilter.type);
    box.replaceChildren(...(rows.length ? rows.map(e=>h("div",{class:"sys-ev"},
      h("div",{class:"row"}, h("span",{class:"mono mut"}, stamp(e.t)), sevTag(e.sev), h("b",{}, EVT[e.type]||e.type)),
      h("div",{class:"m"}, e.msg))) : [h("div",{class:"mut sys-ev"},"（没有事件）")]));
  };
  draw();
  const types = [["","全部类型"], ...(j.types||EVT_ALL).map(t=>[t, EVT[t]||t])];
  return h("div",{},
    card("事件（最近 "+(j.events||[]).length+" 条，新的在上）", [
      h("div",{class:"sys-filters",style:"padding:10px 16px;margin:0"}, inSel(evFilter,"type",types,draw)), box],
      h("button",{class:"btn sm",onclick:()=>show("doctor")},"刷新"), true),
    h("div",{class:"sys-note"}, "存在闪存 /etc/mini-router/state/events.log（最多 200 条；同一类型每小时最多记 10 条，其余只进系统日志）。",
      "设备名、地址来自网络，只作显示。命令行：mr event list。"));
}

const NOTIFY_BLANK = used=>({name:["phone","tg","hook","ntfy","ha"].find(n=>!used.includes(n))||"ch"+(used.length+1),
  type:"telegram", token_secret:"notify_tg_token", chat_id:""});
async function pageNotify(){
  const c = C();
  const n = c.notify || {};
  const chans = n.channels || [];
  // the section appears in router.yaml on the first edit, not by opening this page
  const attach = ()=>{ if (!n.channels) n.channels = chans; if (!c.notify) c.notify = n; touch(); };
  let st = [];
  try { st = (await api("sys.events")).notify || []; } catch(e){}
  const list = h("div");
  const test = name=>h("button",{class:"btn sm",onclick:async e=>{
    e.target.disabled = true;
    try {
      const r = await api("sys.notifytest",{name});
      for (const x of r.results||[]) toast(x.ok ? x.name+"：测试消息已发送" : x.name+"：发送失败 — "+x.error, x.ok?3000:7000);
    } catch(err){ toast(err.message, 6000); } finally { e.target.disabled = false; } }}, "发送测试");
  const draw = ()=>{
    list.replaceChildren(...(chans.length ? chans.map((ch,i)=>{
      const type = inSel(ch,"type",[["telegram","Telegram 机器人"],["webhook","Webhook（ntfy、Bark、Gotify、HA …）"]], v=>{
        if (v==="webhook"){ delete ch.token_secret; delete ch.chat_id; ch.url_secret ||= "notify_webhook_url"; ch.format ||= "json"; }
        else { delete ch.url_secret; delete ch.format; ch.token_secret ||= "notify_tg_token"; ch.chat_id ||= ""; }
        attach(); draw(); });
      const rows = [...field("名称", inText(ch,"name",{maxlength:15, class:"mono"})), ...field("类型", type)];
      if (ch.type==="webhook") rows.push(
        ...field("URL 引用名", inText(ch,"url_secret",{class:"mono"}), "secrets.yaml 里的名字"),
        ...field("URL", inSecret(ch,"url_secret"), "完整地址（通常带密钥），只写入 secrets.yaml，页面不会显示"),
        ...field("格式", inSel(ch,"format",[["json","JSON（Gotify、Bark、Home Assistant、Slack …）"],["text","纯文本 + Title 头（ntfy）"]])));
      else rows.push(
        ...field("Token 引用名", inText(ch,"token_secret",{class:"mono"}), "secrets.yaml 里的名字"),
        ...field("Bot Token", inSecret(ch,"token_secret"), "@BotFather 给的 123456789:AA…，只写入 secrets.yaml"),
        ...field("Chat ID", inText(ch,"chat_id",{class:"mono", placeholder:"123456789 / -1001234567890 / @频道名"}), "先给机器人发一条消息，再从 getUpdates 里找 chat.id"));
      rows.push(...field("经代理发送", inBool(ch,"via_proxy",attach), "经 sing-box 的本机入口发送（Telegram 被墙时）；代理没开时直接发送"));
      return h("div",{class:"sys-chan"}, form(...rows), h("div",{class:"row",style:"margin-top:8px;justify-content:flex-end"}, test(ch.name),
        h("button",{class:"btn sm d",onclick:()=>{ chans.splice(i,1); attach(); draw(); }},"删除")));
    }) : [h("div",{class:"mut",style:"padding:10px 16px"},"还没有通知渠道。")]));
  };
  draw();
  const add = h("button",{class:"btn sm p",onclick:()=>{ if (chans.length>=4) return toast("最多 4 个渠道"); chans.push(NOTIFY_BLANK(chans.map(x=>x.name))); attach(); draw(); }},"+ 添加渠道");
  const cur = new Set(n.events && n.events.length ? n.events : EVT_ALL.filter(t=>t!=="apply"));
  const evBoxes = h("div",{class:"row"}, EVT_ALL.map(t=>h("label",{}, h("input",{type:"checkbox", checked:cur.has(t), onchange:e=>{
    e.target.checked ? cur.add(t) : cur.delete(t); n.events = EVT_ALL.filter(x=>cur.has(x)); attach(); }}), " "+EVT[t])));
  const num = (key, def, attrs)=>h("input",Object.assign({type:"number", value:n[key]??"", placeholder:String(def), style:"max-width:110px",
    oninput:e=>{ if (e.target.value==="") delete n[key]; else n[key]=Number(e.target.value); attach(); }}, attrs));
  const quiet = h("input",{type:"text", class:"mono", value:n.quiet_hours||"", placeholder:"23:00-07:00", style:"max-width:140px",
    oninput:e=>{ if (e.target.value.trim()) n.quiet_hours=e.target.value.trim(); else delete n.quiet_hours; attach(); }});
  const status = st.length ? roTable(["渠道","类型","待发送","上次成功","错误","状态"], st.map(x=>[mono(x.name), x.type, String(x.pending),
    when(x.last_ok), x.error ? h("span",{class:"err",title:x.error}, when(x.error_at)+"：", x.error) : dash(""),
    x.held==="retry" ? "等待重试"+(x.retry_in?"（"+fmtDur(x.retry_in)+"后）":"") : x.held==="rate" ? "超过每小时上限，稍后合并发送" :
      x.held==="quiet_hours" ? "免打扰时段，结束后发送" : x.pending ? "发送中" : h("span",{class:"tag ok"},"正常")])) :
    h("div",{class:"mut",style:"padding:10px 16px"},"（保存并应用后显示状态）");
  return h("div",{},
    card("通知渠道", [h("div",{class:"sys-note",style:"padding:0 16px"},
      "事件推送到手机：Telegram 机器人，或任何接受 POST 的地址（ntfy、Bark、Gotify、Home Assistant 等）。没有常驻进程：事件发生时发送，",
      "失败后按 1、2、4 … 30 分钟重试，断网期间的事件恢复后合并成一条补发。“发送测试”用已应用的配置。"), list], add, true),
    card("推送哪些事件", form(
      ...field("事件类型", evBoxes, "默认除“配置更改”外全部（自己改的配置一般不用提醒）"),
      ...field("每小时上限", num("rate", 10, {min:1, max:60}), "每个渠道每小时最多几条消息，多出的稍后合并发送"),
      ...field("免打扰时段", quiet, "路由器时间，例如 23:00-07:00：期间只发警告 / 风险，其余等结束后发送"),
      ...field("后台体检（分钟）", num("doctor_interval", chans.length?30:0, {min:0, max:1440}), "每隔多久后台跑一次 mr doctor，新问题记为事件；0 = 关闭。有渠道时默认 30"),
      ...field("自动修复", inBool(n,"auto_heal",attach), "后台体检时先重启已启用但没在运行的服务（每个服务 10 分钟内最多一次），记为体检事件；需要后台体检"),
      ...field("检查新版本", inBool(n,"update_check",attach), "每天查一次 GitHub 上的新版本，有新版本记为事件；只提醒，不会下载或安装"))),
    card("发送状态", status, null, true));
}
registerPage("status", "doctor", "体检与事件", 60, ()=>tabs([["doctor","体检",pageDoctor], ["events","事件",pageEvents], ["notify","通知",pageNotify]]));
})();
