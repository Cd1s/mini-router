// mini-router web UI — dns module pages (dnsmasq: DNS, DHCP, RA; stubby DoT). Uses the helpers in
// ui/core.js; see docs/MODULES.md and docs/modules/dns.md.
"use strict";
(()=>{
addCSS(`
.dns-bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:10px 16px;border-bottom:1px solid var(--line)}
.dns-bar input[type=search]{font:inherit;color:var(--fg);background:var(--in);border:1px solid var(--line);border-radius:5px;padding:4px 8px;min-height:28px;width:220px;max-width:100%}
.dns-note{padding:10px 16px 0;color:var(--mut);font-size:12px;line-height:1.6}
.dns-note code{font-size:12px}
.dns-log{max-height:360px}
.dns-sub{color:var(--mut);font-size:12px;margin-left:6px}
`);

const RTYPES = ["A","AAAA","CNAME","PTR","SRV","TXT"];
const RA_MODES = [["","SLAAC（默认，ra-only）"],["slaac","SLAAC（ra-only）"],["stateless","SLAAC + 无状态 DHCPv6（ra-stateless）"],["stateful","有状态 DHCPv6 + SLAAC"]];
const UPSTREAMS = [["isp","运营商 DNS（PPPoE 下发）"],["manual","手动指定上游"],["dot","全部走 DoT 加密（stubby）"]];

// the LAN-side networks as the dns module sees them: main LAN first, then networks[]
const nets = ()=>{ const c=S.cfg; return [{name:"lan", bridge:c.lan.bridge||"br-lan", ipv4:c.lan.ipv4||"", raObj:c.lan, pool:()=>c.dhcp, main:true},
  ...(c.networks||[]).map(n=>({name:n.name, bridge:"br-"+n.name, ipv4:n.ipv4||"", raObj:n, pool:()=>n.dhcp, net:n}))]; };
const routerIP = cidr=>(cidr||"").split("/")[0];
const mono = s=>h("span",{class:"mono"}, s);
const remain = (exp, now)=> !exp ? "永久" : exp<=now ? "已过期" : fmtDur(exp-now);
// a DHCP-supplied name dnsmasq would read as a lease time / keyword ("12345", "5m", "ignore") falls back to host-N
const cleanName = (s, ip)=>{ s=String(s||"").replace(/[^A-Za-z0-9-]/g,"-").replace(/^-+|-+$/g,"").slice(0,63); return s && !/^([0-9]+[smhdwSMHDW]?|infinite|ignore)$/.test(s) ? s : "host-"+ip.split(".").pop(); };
// widgets bound to an object that may not exist in S.cfg yet: attach it on the first edit
const lazy = (parent, key, init)=>{ const o = parent[key] || init(); return {o, attach:()=>{ if(!parent[key]) parent[key]=o; touch(); }}; };
const onEdit = (el, fn)=>{ el.addEventListener("input", fn); el.addEventListener("change", fn); return el; };
// Wake-on-LAN (sys.wol): magic packet to the device's network broadcast; the router checks MAC and network.
// mac: a string or a function (a row whose MAC field may still be edited)
const wakeBtn = (mac, network)=>h("button",{class:"btn sm",title:"发送网络唤醒（WOL）魔术包；设备要在 BIOS / 网卡里开启 Wake-on-LAN",onclick:async()=>{
  const target = typeof mac==="function" ? mac() : mac;
  try { const r = await api("sys.wol", network ? {target, network} : {target}); toast("已发送唤醒包："+r.mac+" → "+r.broadcast+"（"+r.dev+"）", 4000); }
  catch(e){ toast("唤醒失败："+e.message, 5000); } }}, "唤醒");

// ---------------- 状态 › 终端设备 ----------------
registerPage("status", "clients", "终端设备", 20, async ()=>{
  let filter = "", ls = {}, cl = {}, pz = [];
  const body = h("div"), info = h("span",{class:"mut",style:"flex:1"});
  const load = async ()=>{ [ls, cl, pz] = await Promise.all([api("dns.leases"), api("clients").catch(()=>({stations:[]})),
    api("dev.paused").then(j=>j.paused||[]).catch(()=>[])]); render(); };
  const render = ()=>{
    const now = ls.now || Date.now()/1000;
    const byMac = {}; for (const l of ls.leases||[]) byMac[l.mac.toLowerCase()] = l;
    const devOf = {}; for (const d of S.cfg.devices||[]) for (const m of d.macs||[]) devOf[m.toLowerCase()] = d; // 网络 › 设备
    const cfgMacs = new Set([...(S.cfg.dhcp.hosts||[]).map(x=>(x.mac||"").toLowerCase()), ...Object.keys(devOf).filter(m=>devOf[m].ip)]);
    const paused = {}; for (const p of pz) paused[p.mac.toLowerCase()] = p;
    const match = (...xs)=>!filter || xs.some(x=>String(x||"").toLowerCase().includes(filter));
    // 暂停上网: a device of the inventory is paused as a whole (all its MACs), anything else by MAC
    const pauseCtl = (mac, name)=>{
      const d = devOf[mac], p = paused[mac], target = d ? d.name : mac, label = d ? d.name : (name && name!=="*" ? name : mac);
      return p ? [h("span",{class:"tag warn"},"已暂停 · "+pauseLeft(p)), h("button",{class:"btn sm",onclick:async()=>{
          try { await api("dev.unpause",{target}); toast("已恢复 "+label); await load(); } catch(e){ toast(e.message,4000); } }},"恢复")]
        : h("button",{class:"btn sm",title:"暂停它的外网访问（不改配置，到时自动恢复）",onclick:()=>pauseDlg(target, label, load)},"暂停");
    };
    const leaseRows = (ls.leases||[]).filter(l=>match(l.name,l.ip,l.mac,l.network)).map(l=>{
      const mac = l.mac.toLowerCase(), d = devOf[mac];
      const st = l.static ? h("span",{class:"tag ok"},"静态") : cfgMacs.has(mac) ? h("span",{class:"tag warn"},"待应用") :
        h("button",{class:"btn sm",title:"把当前地址固定给这台设备",onclick:e=>{
          if (d) d.ip = l.ip; else S.cfg.dhcp.hosts.push({name:cleanName(l.name,l.ip), mac, ip:l.ip});
          touch(); e.target.replaceWith(h("span",{class:"tag warn"},"待应用")); }},"设为静态");
      const rel = confirmBtn("释放", "释放 "+l.ip+"（"+l.mac+"）的租约？\n设备下次续约时会重新申请地址；适合清理已离线设备或把地址腾给静态分配。", async()=>{
        await api("dns.release",{ip:l.ip, mac:l.mac}); toast("已释放 "+l.ip); await load(); });
      const name = d ? h("span",{}, d.name, l.name && l.name!=="*" && l.name.toLowerCase()!==d.name ? h("span",{class:"dns-sub"}, l.name) : null)
        : l.name==="*" ? h("span",{class:"mut"},"-") : l.name;
      return [name, mono(l.ip), mono(l.mac), l.network||"-", remain(l.expires, now), h("span",{class:"row"}, st, pauseCtl(mac, l.name), wakeBtn(l.mac, l.network), rel)];
    });
    const v6Rows = (ls.leases6||[]).filter(l=>match(l.name,l.ip,l.duid)).map(l=>[l.name==="*"?"-":l.name, mono(l.ip), mono(l.iaid),
      h("span",{class:"mono",title:l.duid}, (l.duid||"").slice(0,23)+((l.duid||"").length>23?"…":"")), remain(l.expires, now)]);
    const wifiRows = (cl.stations||[]).filter(x=>{ const l=byMac[x.mac.toLowerCase()]||{}; return match(l.name,l.ip,x.mac,x.ifname); }).map(x=>{
      const l=byMac[x.mac.toLowerCase()]||{};
      return [l.name&&l.name!=="*"?l.name:"-", mono(l.ip||"-"), mono(x.mac), x.ifname, x.signal, mono(x.tx_rate), mono(x.rx_rate), fmtDur(x.connected)]; });
    info.textContent = tr((ls.leases||[]).length+" 个 DHCP 租约 · "+(cl.stations||[]).length+" 个无线终端");
    // replaceChildren() would render a null argument as the text "null": drop the optional card instead
    body.replaceChildren(...[
      card("DHCP 租约（"+leaseRows.length+"）", roTable(["名称","IPv4","MAC","网络","剩余","操作"], leaseRows), null, true),
      v6Rows.length ? card("DHCPv6 租约（"+v6Rows.length+"）", roTable(["名称","IPv6","IAID","DUID","剩余"], v6Rows), null, true) : null,
      card("无线终端（"+wifiRows.length+"）", roTable(["名称","IP","MAC","接口","信号","发送速率","接收速率","已连接"], wifiRows), null, true)].filter(Boolean));
  };
  await load();
  return h("div",{}, h("div",{class:"card"}, h("div",{class:"dns-bar",style:"border-bottom:0"},
      h("input",{type:"search", placeholder:"筛选：名称 / IP / MAC", oninput:e=>{ filter=e.target.value.trim().toLowerCase(); render(); }}), info,
      h("button",{class:"btn sm",onclick:()=>load().catch(e=>toast(e.message,4000))},"刷新"))), body);
});

// ---------------- 网络 › DHCP ----------------
const poolsTab = ()=>{
  const c = S.cfg;
  const tb = h("tbody");
  const draw = ()=>{
    const rows = (c.networks||[]).map(n=>{
      const {o:p, attach} = lazy(n, "dhcp", ()=>({enabled:false}));
      const row = h("tr",{}, h("td",{}, h("b",{},n.name), h("div",{class:"mono mut"}, n.ipv4||"")),
        h("td",{}, inBool(p,"enabled",on=>{ if(on){ p.start ||= 100; p.end ||= 199; p.lease ||= "12h"; } attach(); draw(); })),
        h("td",{}, inNum(p,"start")), h("td",{}, inNum(p,"end")), h("td",{}, inText(p,"lease",{placeholder:"12h"})));
      return onEdit(row, attach);
    });
    tb.replaceChildren(...(rows.length ? rows : [h("tr",{}, h("td",{colspan:5,class:"mut"},"没有其他网络（访客 / IoT 网络在 网络 › LAN 内网 中添加）"))]));
  };
  draw();
  const base = routerIP(c.lan.ipv4).replace(/\.\d+$/,".");
  return h("div",{},
    card("主 LAN（"+(c.lan.bridge||"br-lan")+" · "+(c.lan.ipv4||"")+"）", form(
      ...field("地址池起始", inNum(c.dhcp,"start"), "主机号，例如 100 → "+base+"100"),
      ...field("地址池结束", inNum(c.dhcp,"end")),
      ...field("租期", inText(c.dhcp,"lease",{placeholder:"12h"}), "如 30m、12h、1d、infinite；最短 2m"),
      ...field("本地域名", inText(c.dhcp,"domain"), "设备名会解析为 <名称>."+(c.dhcp.domain||"lan")))),
    card("其他网络的地址池", [h("div",{class:"dns-note"},"起始 / 结束是网络内的主机号；关闭后该网络不发地址（静态配置的设备仍可上网）。"),
      h("div",{class:"tw"}, h("table",{}, h("thead",{}, h("tr",{}, ["网络","DHCP","起始","结束","租期"].map(x=>h("th",{},x)))), tb))], null, true));
};

const hostsTab = ()=>{
  const c = S.cfg; const arr = c.dhcp.hosts;
  const tb = h("tbody");
  const leaseOf = mac=>{ const m=(c.dhcp.host_leases||{}); const k=Object.keys(m).find(k=>k.toLowerCase()===String(mac||"").toLowerCase()); return k?m[k]:""; };
  const setLease = (mac, v)=>{ c.dhcp.host_leases ||= {}; const m=c.dhcp.host_leases;
    for (const k of Object.keys(m)) if (k.toLowerCase()===String(mac||"").toLowerCase()) delete m[k];
    if (v && mac) m[String(mac).toLowerCase()] = v; touch(); };
  const draw = ()=>{
    tb.replaceChildren();
    if (!arr.length) tb.append(h("tr",{}, h("td",{colspan:5,class:"mut"},"（空）— 可在 状态 › 终端设备 中一键“设为静态”")));
    arr.forEach((row,i)=>{
      const macIn = inText(row,"mac",{placeholder:"aa:bb:cc:dd:ee:ff"});
      let oldMac = row.mac;
      macIn.addEventListener("change", ()=>{ const l=leaseOf(oldMac); if(l){ setLease(oldMac,""); setLease(row.mac,l); } oldMac=row.mac; });
      const lease = h("input",{type:"text", value:leaseOf(row.mac), placeholder:"默认（"+(c.dhcp.lease||"12h")+"）", oninput:e=>setLease(row.mac, e.target.value.trim())});
      tb.append(h("tr",{}, h("td",{}, inText(row,"name",{placeholder:"nas"})), h("td",{}, macIn), h("td",{}, inText(row,"ip",{placeholder:routerIP(c.lan.ipv4).replace(/\.\d+$/,".x")})),
        h("td",{style:"width:130px"}, lease),
        h("td",{style:"width:1%;white-space:nowrap"}, wakeBtn(()=>row.mac), " ", h("button",{class:"btn sm d",onclick:()=>{ setLease(row.mac,""); arr.splice(i,1); touch(); draw(); }},"删除"))));
    });
  };
  draw();
  return card("静态地址分配", [h("div",{class:"dns-note"},"按 MAC 固定 IPv4 地址；主机名同时成为本地 DNS 名称（"+"<名称>."+(c.dhcp.domain||"lan")+"）。IP 可以在任一网络内。租期留空 = 使用地址池租期，服务器可填 infinite。"),
    h("div",{class:"tw"}, h("table",{}, h("thead",{}, h("tr",{}, ["主机名","MAC","IPv4","租期",""].map(x=>h("th",{},x)))), tb))],
    h("button",{class:"btn sm p",onclick:()=>{ arr.push({name:"",mac:"",ip:""}); touch(); draw(); }},"+ 添加"), true);
};

const optionsTab = ()=>{
  const cards = nets().filter(n=>n.main || (n.pool()&&n.pool().enabled)).map(n=>{
    const p = n.pool();
    // a pool created by an older UI / hand-written YAML may lack the list: attach one on first edit
    const opts = Array.isArray(p.options) ? p.options : [];
    const ot = etable(opts, [{k:"code",l:"选项号",t:"num",w:"110px"},{k:"value",l:"值（逗号分隔）",ph:"例如 192.168.1.10"}], {code:0,value:""}, {noMove:true});
    const attachOpts = ()=>{ if (p.options !== opts){ p.options = opts; touch(); } };
    for (const e of [ot.el, ot.add]){ onEdit(e, attachOpts); e.addEventListener("click", attachOpts); }
    return card(n.name+"（"+n.bridge+"）", [form(
        ...field("DNS 服务器（option 6）", inList(p,"dns",{placeholder:"留空 = 路由器 "+routerIP(n.ipv4)}), "只填 IPv4；例如家里另有 AdGuard / Pi-hole 时指向它"),
        ...field("NTP 服务器（option 42）", inList(p,"ntp",{placeholder:"留空 = 不下发"}), "只能填 IPv4 地址"),
        ...field("搜索域（option 119）", inList(p,"search",{placeholder:"例如 lan"}))),
      h("div",{style:"margin-top:14px"}, h("div",{class:"row",style:"margin-bottom:6px"}, h("b",{},"其他选项"), h("span",{class:"mut",style:"flex:1"},"按编号下发，例如 26 = MTU，66/67 = PXE，121 = 静态路由（必须以 0.0.0.0/0,<网关> 开头）"), ot.add), ot.el)]);
  });
  return h("div",{}, h("div",{class:"mut",style:"margin-bottom:12px;font-size:12px"},"网关（option 3）总是本路由器；1/3/6/12/15/42/50-61/119 由系统管理，不能在“其他选项”里重复设置。值只允许字母、数字和 . _ : / @ + = -，多个值用逗号分隔。"), cards);
};

const raTab = ()=>{
  const box = h("div");
  const draw = ()=>{
    box.replaceChildren(h("div",{class:"mut",style:"margin-bottom:12px;font-size:12px"},"前缀来自 WAN 的 IPv6 前缀代理（dhcpcd PD），dnsmasq 按网桥上的全局地址自动构造。SLAAC 兼容性最好（Android 只支持 SLAAC）；需要让设备拿到可追踪的固定段地址时用“有状态 DHCPv6 + SLAAC”。"),
      ...nets().map(n=>{
        const holder = n.main ? {o:S.cfg.dhcp, attach:touch} : lazy(n.net, "dhcp", ()=>({enabled:false}));
        const ral = lazy(holder.o, "ipv6", ()=>({}));
        const r = ral.o; const attach = ()=>{ holder.attach(); ral.attach(); };
        const stateful = r.mode==="stateful";
        const body = form(
          ...field("启用 RA", inBool(n.raObj,"ipv6_ra",()=>draw()), n.main?"与 网络 › LAN 内网 的开关相同":"与网络设置中的 ipv6_ra 相同"),
          ...(n.raObj.ipv6_ra ? [
            ...field("模式", inSel(r,"mode",RA_MODES,()=>{ attach(); draw(); })),
            ...(stateful ? [...field("地址范围起始", inText(r,"start",{placeholder:"::1000"}), "接口 ID（前缀后半部分），例如 ::1000"), ...field("地址范围结束", inText(r,"end",{placeholder:"::ffff"}))] : []),
            ...field("前缀 / 租约有效期", inText(r,"lease",{placeholder:"12h"}), "必须带单位：如 2h、12h、1d、infinite"),
            ...field("RDNSS / DHCPv6 DNS", inList(r,"dns",{placeholder:"留空 = 路由器"}), "IPv6 地址，“::” 表示路由器自己的全局地址"),
            ...field("RA 间隔（秒）", inNum(r,"ra_interval",{placeholder:"60"}), "0 = 默认 60；4-1800"),
            ...field("路由器生存期（秒）", inNum(r,"ra_lifetime",{placeholder:"1800"}), "0 = 默认 1800；60-9000"),
            ...field("路由器优先级", inSel(r,"ra_priority",[["","中（默认）"],["high","高"],["low","低"]])),
            ...field("通告 MTU", inNum(r,"ra_mtu"), "0 = 不通告；PPPoE 可填 1492")] : []));
        return card(n.name+"（"+n.bridge+"）", onEdit(body, e=>{ if (!(e.target.closest&&e.target.closest("label.sw"))) attach(); }));
      }));
  };
  draw();
  return box;
};

registerPage("network", "dhcp", "DHCP / IPv6 RA", 40, ()=>tabs([
  ["pools","地址池", poolsTab], ["hosts","静态分配", hostsTab], ["options","DHCP 选项", optionsTab], ["ra","IPv6 通告 (RA)", raTab]]));

// ---------------- 网络 › DNS ----------------
// 防绕过（dns.sovereignty, #45）：让设备留在路由器的 DNS 上
const sovCard = d=>{
  const sv = lazy(d, "sovereignty", ()=>({}));
  const canary = h("label",{class:"sw"}, h("input",{type:"checkbox", checked: sv.o.firefox_canary!==false, onchange:e=>{ sv.o.firefox_canary=e.target.checked; }}), h("span"));
  return card("防绕过（DNS 主导权）", onEdit(form(
    ...field("Firefox 金丝雀", canary, "use-application-dns.net 返回“不存在”：Firefox 不会自己开启 DoH（默认开）"),
    ...field("iCloud 专用代理", inSel(sv.o,"private_relay",[["","允许（默认）"],["block","在本网络关闭"]]), "关闭后苹果设备会提示本网络不支持专用代理"),
    ...field("拦截 DoT / DoQ", inBool(sv.o,"block_dot"), "局域网连任何 853 端口都被立即拒绝，设备改用路由器 DNS；手动填了“私人 DNS 主机名”的安卓设备会解析失败，需改回“自动”"),
    ...field("DoH 服务器 IP 列表", inText(sv.o,"doh_blocklist_file",{placeholder:"/etc/mini-router/dns/doh.ips"}), "文件里每行一个 IP 或网段；局域网连这些地址的 443 端口被拒绝")), ()=>sv.attach()));
};
const basicTab = ()=>{
  const c = S.cfg, d = c.dns; const box = h("div");
  const stub = lazy(c.services, "stubby", ()=>({enabled:false}));
  const draw = ()=>{
    const dotPort = d.dot && d.dot.port || 5453;
    const dotT = etable(d.dot.servers, [{k:"address",l:"地址",ph:"1.1.1.1"},{k:"name",l:"TLS 名称",ph:"cloudflare-dns.com"},{k:"port",l:"端口",t:"num",w:"90px",ph:"853"}], {address:"",name:"",port:0});
    box.replaceChildren(
      card("上游 DNS", form(
        ...field("上游", inSel(d,"upstream",UPSTREAMS,()=>draw())),
        ...(d.upstream==="manual" ? [...field("上游服务器", inList(d,"servers",{placeholder:"1.1.1.1, 223.5.5.5, 9.9.9.9#9953"}), "IP 或 IP#端口，按响应速度自动选择")] : []),
        ...(d.upstream==="dot" ? [...field("", h("span",{class:"mut"},"所有查询经 stubby（127.0.0.1#"+dotPort+"）走 TLS。NTP 域名用下方“引导 DNS”明文解析，否则开机时钟不准会导致 TLS 失败。"))] : []),
        ...(d.upstream==="isp"||!d.upstream ? [...field("", h("span",{class:"mut"},"使用 PPPoE 拨号下发的 DNS（WAN 需开启“使用运营商 DNS”）；出国换网络时自动跟随。"))] : []))),
      card("DoT 加密 DNS（stubby）", [form(
        ...field("启用 stubby", inBool(stub.o,"enabled",()=>{ stub.attach(); draw(); }), "与 服务 页的开关相同；分流到 127.0.0.1#"+dotPort+" 或上游选 DoT 时必须开启"),
        ...field("监听端口", inNum(d.dot,"port"), "只监听 127.0.0.1，不对局域网开放"),
        ...field("引导 DNS", inList(d.dot,"bootstrap",{placeholder:"留空 = DoT 服务器的 53 端口"}), "仅在上游为 DoT 时用于解析 NTP 服务器域名")),
        h("div",{style:"margin-top:12px"}, h("div",{class:"row",style:"margin-bottom:6px"}, h("b",{},"DoT 服务器"), h("span",{class:"mut",style:"flex:1"},"TLS 名称用于校验证书"), dotT.add), dotT.el)]),
      card("缓存与安全", form(
        ...field("缓存条数", inNum(d,"cache_size")),
        ...field("最小缓存 TTL (秒)", inNum(d,"min_cache_ttl"), "最大 3600"),
        ...field("过期缓存可用 (秒)", inNum(d,"use_stale_cache"), "上游慢时先用过期记录应答，0 关闭"),
        ...field("不缓存失败结果", inBool(d,"no_negcache")),
        ...field("EDNS 包大小", inNum(d,"edns_packet_max")),
        ...field("重绑定保护", inBool(d,"rebind_protection"), "上游返回私有地址时丢弃（本地记录不受影响）"),
        ...field("仅服务本地网络", inBool(d,"local_service")),
        ...field("劫持 LAN DNS", inBool(d,"redirect"), "LAN 设备发往任何 53 端口的请求都交给路由器"),
        ...field("额外 hosts 文件", inList(d,"addn_hosts")),
        ...field("上游服务器文件", inText(d,"servers_file",{placeholder:"留空"})))),
      sovCard(d));
  };
  draw();
  return box;
};

const recordsTab = ()=>{
  const d = S.cfg.dns;
  const t = etable(d.records, [{k:"name",l:"名称",ph:"nas.lan"},{k:"type",l:"类型",t:"sel",o:RTYPES,w:"100px"},{k:"value",l:"值",ph:"192.168.1.10"}], {name:"",type:"A",value:""});
  const help = roTable(["类型","名称","值","说明"], [
    ["A / AAAA", mono("nas 或 nas.lan"), mono("192.168.1.10 / fd00::10"), "不带点的名称同时生成 nas 和 nas."+(S.cfg.dhcp.domain||"lan")+"，并自动提供反向解析"],
    ["A / AAAA", mono("*.home.example.com"), mono("192.168.1.6"), "域名本身及所有子域（适合 Lucky 反代的内网直连）；只应答对应的 A 或 AAAA，另一种仍走上游，需要时两种都加"],
    ["CNAME", mono("photos.lan"), mono("nas.lan"), "目标必须是本地已知名称（记录 / DHCP 设备 / hosts）"],
    ["PTR", mono("192.168.1.11"), mono("printer.lan"), "名称可填 IP，自动转换为 in-addr.arpa / ip6.arpa"],
    ["SRV", mono("_smb._tcp.lan"), mono("nas.lan:445[:优先级[:权重]]"), ""],
    ["TXT", mono("nas.lan"), mono("任意文本"), "最多 255 字符，不能含 \" 和 \\"]]);
  return h("div",{}, card("本地 DNS 记录", [h("div",{class:"dns-note"},"由路由器直接应答，优先于上游和分流；应用后会逐条回读 A/AAAA 记录，失败自动回滚。"), t.el], t.add, true),
    card("格式", help, null, true));
};

const splitTab = ()=>{
  const c = S.cfg;
  const splitEd = h("div");
  const openList = async name=>{
    const j = await api("dnslist",{name});
    const ta = h("textarea",{rows:16}, j.content);
    splitEd.replaceChildren(card("域名列表 · "+name, [h("div",{class:"mut",style:"margin-bottom:8px"}, j.path+" — 每行一个域名，# 开头为注释"), ta,
      h("div",{class:"row",style:"margin-top:10px"}, h("button",{class:"btn p",onclick:async()=>{
        try { await api("dnslist",{name, content:ta.value, save:true}); toast("已保存，点击底部“保存并应用”生效"); S.orig=""; touch(); } catch(e){ toast("保存失败："+e.message,4000); }
      }},"保存列表"), h("button",{class:"btn",onclick:()=>splitEd.replaceChildren()},"关闭"))]));
  };
  const split = etable(c.dns.split, [{k:"name",l:"名称"},{k:"domains_file",l:"域名列表文件",ph:"/etc/mini-router/dns/xxx.domains"},{k:"server",l:"上游服务器",ph:"127.0.0.1#5453"}],
    {name:"",domains_file:"/etc/mini-router/dns/new.domains",server:""});
  return h("div",{}, card("DNS 分流", [h("div",{class:"dns-note"},"列表中的域名（含子域）交给指定上游解析，例如 stubby DoT：127.0.0.1#"+((c.dns.dot||{}).port||5453)+"。优先级：本地记录 > 更长（更具体）的域名 > 较短的域名 > 默认上游。同一个域名不要同时出现在分流列表和代理列表里（dnsmasq 会把两个上游当成一组轮流使用）。"), split.el,
      h("div",{class:"row",style:"padding:10px 16px"}, h("span",{class:"mut"},"编辑已保存的列表："), c.dns.split.filter(x=>x.name).map(x=>h("button",{class:"btn sm",onclick:()=>openList(x.name).catch(e=>toast(e.message,4000))},x.name)))], split.add, true),
    splitEd);
};

const statsTab = ()=>{
  const box = h("div"); let logFilter = ""; let mins = "10"; let lastLog = null;
  const pct = (a,b)=> b>0 ? (a*100/b).toFixed(1)+"%" : "-";
  const stat = (l,v,sub,p)=>h("div",{class:"card stat"}, h("div",{class:"l"},l), h("div",{class:"v"},v), sub?h("div",{class:"s"},sub):null, p!==undefined?h("div",{class:"bar"},h("i",{style:"width:"+Math.min(100,p).toFixed(0)+"%"})):null);
  const logBox = h("div");
  const drawLog = j=>{
    lastLog = j;
    const on = j.until > 0;
    const lines = (j.lines||[]).filter(l=>!logFilter || l.toLowerCase().includes(logFilter));
    logBox.replaceChildren(card(h("span",{},h("span",{class:"dot "+(on?"ok":"")}),"查询日志", h("span",{class:"dns-sub"}, on?"记录中，"+new Date(j.until*1000).toLocaleTimeString()+" 自动关闭":"未开启")), [
      h("div",{class:"dns-bar"}, on ? h("button",{class:"btn sm",onclick:()=>setLog(false)},"立即关闭") :
          [inSel({v:mins},"v",[["5","5 分钟"],["10","10 分钟"],["30","30 分钟"],["60","60 分钟"]],v=>{ mins=v; }), h("button",{class:"btn sm p",onclick:()=>setLog(true)},"开启")],
        h("input",{type:"search",placeholder:"筛选：域名 / 客户端 IP",value:logFilter,oninput:e=>{ logFilter=e.target.value.trim().toLowerCase(); drawLog(lastLog); }}),
        h("button",{class:"btn sm",onclick:()=>api("dns.querylog").then(drawLog).catch(e=>toast(e.message,4000))},"刷新")),
      h("div",{class:"dns-note",style:"padding-bottom:10px"},"默认关闭，只在排查时临时开启：开关会重启 dnsmasq（缓存清空、DNS 中断约 1 秒），到时自动关闭，重启路由器后也不会保留。日志写入系统日志的内存缓冲。"),
      h("pre",{class:"dns-log",style:"margin:0 16px 16px"}, lines.length ? lines.join("\n") : (on?"（暂无查询）":"（未开启）"))]));
  };
  const setLog = async on=>{
    try { drawLog(await api("dns.querylog",{on, minutes:Number(mins)})); toast(on?"查询日志已开启 "+mins+" 分钟":"查询日志已关闭"); }
    catch(e){ toast(e.message,4000); }
  };
  const statBox = h("div");
  const draw = async ()=>{
    const j = await api("dns.stats");
    const s = j.dnsmasq || {};
    const total = (s.hits||0)+(s.misses||0);
    const dotPort = (S.cfg.dns.dot||{}).port || 5453;
    const srv = (s.servers||[]).map(x=>[mono(x.server), x.server==="127.0.0.1#"+dotPort?h("span",{class:"tag"},"stubby DoT"):"", x.queries, x.failed, pct(x.failed, x.queries)]);
    statBox.replaceChildren(...[
      j.error ? h("div",{class:"err",style:"margin-bottom:12px"}, j.error) : null,
      h("div",{class:"grid",style:"margin-bottom:18px"},
        stat("缓存命中率", pct(s.hits||0,total), "本地应答 "+(s.hits||0)+" · 转发上游 "+(s.misses||0), total?(s.hits||0)*100/total:0),
        stat("缓存", String(s.cache_size??"-"), "插入 "+(s.insertions??"-")+" · 淘汰 "+(s.evictions??"-")),
        stat("上游模式", (UPSTREAMS.find(u=>u[0]===j.upstream)||[j.upstream,j.upstream||"-"])[1]),
        stat("DHCP 租约", String(j.leases??"-"), "DHCPv6 "+(j.leases6??0))),
      card("上游服务器", roTable(["服务器","","查询","失败","失败率"], srv), h("span",{class:"mut",style:"font-size:12px"},"dnsmasq 启动以来"), true)].filter(Boolean));
    if (j.querylog_until>0 || !lastLog) drawLog(await api("dns.querylog"));
  };
  box.append(statBox, logBox);
  draw().catch(e=>statBox.replaceChildren(h("div",{class:"err"},"读取失败："+e.message)));
  clearInterval(S.timer);
  S.timer = setInterval(()=>{ if (box.isConnected) draw().catch(()=>{}); }, 5000);
  return box;
};

// 去广告（dns.adblock, #30）：dnsmasq 列表，不新增进程
const ADBLOCK_LISTS = [["HaGeZi Multi NORMAL（约 16 万，推荐）","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt"],
  ["HaGeZi Multi LIGHT（约 4.5 万）","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt"],
  ["anti-AD（约 11 万，中文网站）","https://anti-ad.net/domains.txt"]];
const adblockTab = ()=>{
  const d = S.cfg.dns; const box = h("div"); const stat = h("div");
  const ab = lazy(d, "adblock", ()=>({enabled:false, lists:[], allow:[], max_domains:0}));
  const setLists = v=>{ ab.o.lists = v; ab.attach(); };
  const ta = h("textarea",{rows:4, placeholder:"每行一个 https 地址", oninput:e=>setLists(e.target.value.split(/\s+/).filter(Boolean))}, (ab.o.lists||[]).join("\n"));
  const presets = h("div",{class:"row",style:"flex-wrap:wrap;gap:6px;margin-top:6px"}, ADBLOCK_LISTS.map(([l,u])=>h("button",{class:"btn sm",onclick:()=>{
    const cur = ab.o.lists||[]; if (!cur.includes(u)) { setLists([...cur, u]); ta.value = ab.o.lists.join("\n"); }
  }},"+ "+l)));
  const load = async ()=>{
    let j; try { j = await api("dns.adblock"); } catch(e){ stat.replaceChildren(h("span",{class:"mut"},e.message)); return; }
    const last = j.last || null;
    stat.replaceChildren(...[
      h("div",{}, h("b",{}, j.domains ? j.domains.toLocaleString()+" 个域名已拦截" : "还没有列表"),
        j.updated ? h("span",{class:"mut"}," · 更新于 "+new Date(j.updated*1000).toLocaleString()) : null,
        j.running ? h("span",{class:"tag warn",style:"margin-left:6px"},"更新中…") : null,
        j.enabled && j.domains && !j.current ? h("span",{class:"mut"}," · 设置已改，一小时内按新设置重新下载") : null),
      last && last.lists ? h("div",{class:"mut",style:"margin-top:6px;font-size:12px"}, last.lists.map(x=>h("div",{class:"mono"},
        (x.error ? "✗ " : "✓ ")+x.url+"："+(x.error ? x.error : x.domains.toLocaleString()+" 行可用")))) : null,
      last && last.error ? h("div",{style:"color:var(--bad);margin-top:6px"}, "上次更新失败（仍用之前的列表）："+last.error) : null].filter(Boolean));
  };
  const upd = h("button",{class:"btn",onclick:async()=>{
    try { await api("dns.adblock",{update:true}); toast("已开始更新，约半分钟"); setTimeout(load, 4000); setTimeout(load, 15000); setTimeout(load, 40000); }
    catch(e){ toast(e.message,4000); }
  }},"立即更新");
  box.replaceChildren(
    card("去广告", [h("div",{class:"dns-note"},"广告、跟踪、恶意域名直接返回“不存在”。不新增进程：列表变成 dnsmasq 的规则，每小时检查一次、满一天才重新下载；下载失败或内容不对会继续用旧列表。更新时 DNS 停顿 1–2 秒。列表经路由器自己的网络下载（不走代理）。"),
      onEdit(form(
        ...field("启用", inBool(ab.o,"enabled",()=>ab.attach())),
        ...field("列表地址", h("div",{}, ta, presets), "纯域名、hosts、AdGuard（||域名^）或 dnsmasq 格式"),
        ...field("白名单", inList(ab.o,"allow",{placeholder:"example.com, cdn.example.org"}), "这些域名及其子域名永不拦截"),
        ...field("最多域名数", inNum(ab.o,"max_domains"), "0 = 300000；超过就不更新（保护内存）")), ()=>ab.attach())]),
    card("状态", [stat, h("div",{class:"row",style:"margin-top:10px"}, upd, h("span",{class:"mut"},"启用并“保存并应用”后才能更新"))]));
  load();
  return box;
};

registerPage("network", "dns", "DNS", 50, ()=>tabs([
  ["basic","上游与缓存", basicTab], ["records","本地记录", recordsTab], ["split","分流", splitTab], ["adblock","去广告", adblockTab], ["stats","统计 / 查询日志", statsTab]]));
})();
