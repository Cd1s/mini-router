// mini-router web UI — dev module page (网络 › 设备): the device inventory (router.yaml devices, groups)
// with its live state, where each device is used, and 暂停上网 (dev.pause: runtime, no config change).
// Uses only the helpers in ui/core.js; see docs/MODULES.md and docs/modules/dev.md.
"use strict";
(()=>{
addCSS(`
.dev-bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:10px 16px}
.dev-bar input[type=search]{font:inherit;color:var(--fg);background:var(--in);border:1px solid var(--line);border-radius:5px;padding:4px 8px;min-height:28px;width:200px;max-width:100%}
.dev-bar select{max-width:100%}
.dev-sub{color:var(--mut);font-size:12px}
.dev-macs{font-size:12px;line-height:1.5}
.dev-chk{display:flex;flex-wrap:wrap;gap:4px 14px}
.dev-note{padding:10px 16px;color:var(--mut);font-size:12px;line-height:1.6}
.dev-t td{white-space:nowrap}
.dev-t .row{flex-wrap:nowrap}
`);

const TYPES = [["","（未指定）"],["pc","电脑"],["phone","手机"],["tablet","平板"],["tv","电视 / 盒子"],["console","游戏机"],
  ["iot","智能家居"],["server","服务器 / NAS"],["printer","打印机"],["other","其他"]];
const typeName = t=>(TYPES.find(x=>x[0]===t)||[t,t])[1];
const mono = s=>h("span",{class:"mono"}, s);
const lc = s=>String(s||"").toLowerCase();
// devices / groups are attached to S.cfg only on the first edit: visiting the page is not a change
const devs = ()=>S.cfg.devices||[];
const groups = ()=>S.cfg.groups||{};
const attach = ()=>{ S.cfg.devices ||= []; S.cfg.groups ||= {}; };
// a DHCP client name → a device name (lowercase letters, digits, -; starts with a letter)
const cleanName = s=>lc(s).replace(/[^a-z0-9-]+/g,"-").replace(/^[^a-z]+/,"").slice(0,32).replace(/-+$/,"");

// where a device (or group:NAME) is used — the places the router resolves names
function refsOf(name){
  const c = S.cfg, f = c.firewall||{}, out = [];
  for (const x of f.forwards||[]) if (x.to===name) out.push("端口转发 "+x.name);
  for (const x of f.access||[]) if ((x.devices||[]).includes(name)) out.push("设备管控 "+x.name);
  for (const x of c.policy_routes||[]) if (x.device===name) out.push("策略路由 "+x.name);
  for (const x of (c.proxy||{}).bypass||[]) if (x.device===name) out.push("代理例外 "+x.name);
  if (((c.guard||{}).always_bypass||[]).includes(name)) out.push("guard.always_bypass");
  for (const x of c.schedules||[]) if (x.action==="wol" && x.target===name) out.push("计划任务 "+x.name);
  return out;
}
// renaming follows every reference (the change shows in the apply plan)
function renameRefs(from, to){
  const c = S.cfg, f = c.firewall||{}, sw = a=>a.map(d=>d===from?to:d);
  for (const x of f.forwards||[]) if (x.to===from) x.to = to;
  for (const x of f.access||[]) if (x.devices) x.devices = sw(x.devices);
  for (const x of c.policy_routes||[]) if (x.device===from) x.device = to;
  for (const x of (c.proxy||{}).bypass||[]) if (x.device===from) x.device = to;
  if (c.guard && c.guard.always_bypass) c.guard.always_bypass = sw(c.guard.always_bypass);
  for (const x of c.schedules||[]) if (x.action==="wol" && x.target===from) x.target = to;
  for (const g of Object.keys(groups())) S.cfg.groups[g] = sw(S.cfg.groups[g]);
}
const refsCell = refs=>refs.length ? h("span",{title:refs.join("\n"), style:"cursor:help"}, refs.length+" 处") : h("span",{class:"mut"},"—");
const okBtn = t=>h("button",{class:"btn p",onclick:e=>e.target.closest(".modal").remove()}, t||"知道了");

function editDevice(orig, save){
  const o = clone(orig); o.macs ||= []; o.limit ||= {};
  const dom = (S.cfg.dhcp||{}).domain||"lan";
  const m = modal(orig.name ? "编辑设备 · "+orig.name : "添加设备", form(
      ...field("名称", inText(o,"name",{placeholder:"kid-tablet"}), "小写字母、数字和 -，以字母开头；也是它的 DNS 名 <名称>."+dom+"。端口转发、设备管控、策略路由、代理例外里直接写这个名字"),
      ...field("MAC 地址", inList(o,"macs",{placeholder:"aa:bb:cc:dd:ee:ff, …"}), "可填多个（有线 + 无线、手机在本网络的私有 Wi-Fi 地址）"),
      ...field("固定 IPv4", inText(o,"ip",{placeholder:"留空 = 动态分配"}), "填了就是静态 DHCP 分配，端口转发可以写设备名；多个 MAC 共用它时同一时间只能一个在线"),
      ...field("类型", inSel(o,"type",TYPES)),
      ...field("归属", inText(o,"owner",{placeholder:"例如 小明"})),
      ...field("说明", inText(o,"desc")),
      ...field("上下线提醒", inBool(o,"watch"), "上线 / 离线超过 10 分钟记入事件（可推送通知）"),
      ...field("限速 Mbit/s", h("span",{class:"row"}, "↓", inNum(o.limit,"down",{style:"width:90px"}), "↑", inNum(o.limit,"up",{style:"width:90px"})), "0 = 不限；限速的设备不走硬件加速")),
    [h("button",{class:"btn",onclick:()=>m.remove()},"取消"),
     h("button",{class:"btn p",onclick:()=>{
       o.name = String(o.name||"").trim();
       if (!o.name) return toast("请填写名称");
       if (!o.macs.length) return toast("至少填一个 MAC");
       if (o.name!==orig.name && devs().some(d=>d.name===o.name)) return toast("已有设备 "+o.name);
       for (const k of ["down","up"]) if (!(o.limit[k]>0)) delete o.limit[k];
       for (const k of ["ip","type","owner","desc","watch"]) if (!o[k]) delete o[k];
       if (!Object.keys(o.limit).length) delete o.limit;
       save(o); m.remove(); touch(); }},"确定")]);
}

// one device: lease, WiFi, traffic of its current connections, the rules that use it (or its groups)
async function devDetail(d, ls, cl){
  const macs = (d.macs||[]).map(lc), mine = x=>macs.includes(lc(x.mac));
  let tf = [];
  try { tf = ((await api("mon.devices")).devices||[]).filter(mine); } catch(e){}
  const inG = Object.keys(groups()).filter(g=>groups()[g].includes(d.name));
  const refs = [...refsOf(d.name), ...inG.flatMap(g=>refsOf("group:"+g).map(r=>r+" (group:"+g+")"))];
  const list = (a, f)=>a.length ? a.map(x=>h("div",{}, f(x))) : "—";
  modal("设备 · "+d.name, h("dl",{class:"kv"},
    h("dt",{},"MAC"), h("dd",{class:"mono"}, macs.join(" ")),
    h("dt",{},"租约"), h("dd",{}, list((ls.leases||[]).filter(mine), l=>l.ip+" · "+(l.network||"")+(l.expires ? " · 剩余 "+fmtDur(Math.max(0, l.expires-(ls.now||0))) : ""))),
    h("dt",{},"WiFi"), h("dd",{}, list((cl.stations||[]).filter(mine), s=>(s.ssid||s.ifname)+" · "+s.signal+" · "+fmtDur(s.connected))),
    h("dt",{},"流量"), h("dd",{}, list(tf, x=>x.conns+" 个连接 · ↑ "+fmtBytes(x.up)+" ↓ "+fmtBytes(x.down))),
    h("dt",{},"引用"), h("dd",{}, list(refs, r=>r))), [okBtn("关闭")]);
}

registerPage("network", "devices", "设备", 30, async ()=>{
  let filter = "", ls = {}, cl = {}, pz = [];
  const body = h("div"), info = h("span",{class:"mut",style:"flex:1 1 180px"});
  const load = async ()=>{
    [ls, cl, pz] = await Promise.all([api("dns.leases").catch(()=>({})), api("clients").catch(()=>({stations:[]})),
      api("dev.paused").then(j=>j.paused||[]).catch(()=>[])]);
    render();
  };
  const unpause = async (target, label)=>{
    try { await api("dev.unpause",{target}); toast("已恢复 "+label); await load(); } catch(e){ toast(e.message,4000); } };
  const del = (d, i)=>{
    const refs = refsOf(d.name);
    if (refs.length) return modal("设备 "+d.name+" 还在使用", [h("div",{},"先修改这些地方，再删除它："), h("ul",{}, refs.map(r=>h("li",{},r)))], [okBtn()]);
    const inG = Object.keys(groups()).filter(g=>groups()[g].includes(d.name));
    if (!confirm("删除设备 "+d.name+"？"+(inG.length ? "\n同时从分组 "+inG.join("、")+" 中移除。" : ""))) return;
    attach(); S.cfg.devices.splice(i,1);
    for (const g of inG){ const a = S.cfg.groups[g].filter(x=>x!==d.name); if (a.length || refsOf("group:"+g).length) S.cfg.groups[g] = a; else delete S.cfg.groups[g]; }
    touch(); render();
  };
  const editGroup = g=>{
    const o = {name:g||"", members:[...(groups()[g]||[])]};
    const box = h("div",{class:"dev-chk"}, devs().length ? devs().map(d=>h("label",{}, h("input",{type:"checkbox", checked:o.members.includes(d.name), onchange:e=>{
      const s = new Set(o.members); e.target.checked ? s.add(d.name) : s.delete(d.name); o.members = devs().map(x=>x.name).filter(n=>s.has(n)); }}), " "+d.name))
      : h("span",{class:"mut"},"先添加设备"));
    const m = modal(g ? "编辑分组 · "+g : "添加分组", form(
        ...field("名称", inText(o,"name",{placeholder:"kids"}), "小写字母、数字、_ -，以字母开头（最长 15）；其他地方写 group:名称"),
        ...field("成员", box)),
      [h("button",{class:"btn",onclick:()=>m.remove()},"取消"), h("button",{class:"btn p",onclick:()=>{
        const n = String(o.name||"").trim();
        if (!n) return toast("请填写名称");
        if (!o.members.length) return toast("至少选一台设备");
        if (n!==g && groups()[n]) return toast("已有分组 "+n);
        attach();
        if (g && n!==g){ delete S.cfg.groups[g]; renameRefs("group:"+g, "group:"+n); }
        S.cfg.groups[n] = o.members; m.remove(); touch(); render(); }},"确定")]);
  };
  const delGroup = g=>{
    const refs = refsOf("group:"+g);
    if (refs.length) return modal("分组 "+g+" 还在使用", [h("div",{},"先修改这些地方，再删除它："), h("ul",{}, refs.map(r=>h("li",{},r)))], [okBtn()]);
    if (!confirm("删除分组 "+g+"？（设备本身保留）")) return;
    delete S.cfg.groups[g]; touch(); render();
  };

  const render = ()=>{
    const lease = {}; for (const l of ls.leases||[]) lease[lc(l.mac)] = l;
    const wifi = {}; for (const s of cl.stations||[]) wifi[lc(s.mac)] = s;
    const paused = {}; for (const p of pz) paused[lc(p.mac)] = p;
    const mine = new Set(devs().flatMap(d=>(d.macs||[]).map(lc)));
    const match = (...xs)=>!filter || xs.some(x=>lc(x).includes(filter));
    const rows = devs().map((d,i)=>[d,i]).filter(([d])=>match(d.name, d.owner, d.type, d.ip, ...(d.macs||[]))).map(([d,i])=>{
      const macs = (d.macs||[]).map(lc);
      const l = macs.map(m=>lease[m]).find(Boolean), w = macs.map(m=>wifi[m]).find(Boolean), p = macs.map(m=>paused[m]).find(Boolean);
      const inG = Object.keys(groups()).filter(g=>groups()[g].includes(d.name));
      return [
        h("div",{}, h("a",{href:"#", onclick:e=>{ e.preventDefault(); devDetail(d, ls, cl); }}, h("b",{},d.name)), d.watch ? h("span",{class:"tag",style:"margin-left:6px"},"提醒") : null, d.limit ? h("span",{class:"tag warn",style:"margin-left:6px"},"限速") : null, h("div",{class:"dev-sub"}, [d.type?typeName(d.type):"", d.owner||"", inG.map(g=>"#"+g).join(" ")].filter(Boolean).join(" · "))),
        h("div",{class:"dev-macs mono"}, macs.map(m=>h("div",{},m))),
        d.ip ? mono(d.ip) : l ? h("span",{class:"mono mut",title:"动态分配的当前地址"}, l.ip) : h("span",{class:"mut"},"—"),
        h("span",{class:"row"}, w ? h("span",{class:"tag ok",title:w.ifname+" · "+w.signal},"WiFi 在线") : l ? h("span",{class:"tag"},"有租约") : h("span",{class:"mut"},"—"),
          p ? h("span",{class:"tag warn"},"已暂停 · "+pauseLeft(p)) : null),
        refsCell(refsOf(d.name)),
        h("span",{class:"row",style:"flex-wrap:nowrap"},
          p ? h("button",{class:"btn sm",onclick:()=>unpause(d.name, d.name)},"恢复") : h("button",{class:"btn sm",onclick:()=>pauseDlg(d.name, d.name, load)},"暂停"),
          h("button",{class:"btn sm",onclick:()=>editDevice(d, v=>{ attach(); if (v.name!==d.name) renameRefs(d.name, v.name); S.cfg.devices[i] = v; render(); })},"编辑"),
          h("button",{class:"btn sm d",onclick:()=>del(d, i)},"删除"))];
    });
    // add from a DHCP client, or move a dhcp.hosts entry into the inventory (a MAC may be in one place only)
    const hosts = S.cfg.dhcp.hosts||[], hostMacs = new Set(hosts.map(x=>lc(x.mac)));
    const cand = (ls.leases||[]).filter(l=>!mine.has(lc(l.mac)) && !hostMacs.has(lc(l.mac)));
    const pick = h("select",{style:"width:auto;max-width:220px",onchange:e=>{
      const v = e.target.value; e.target.value = "";
      if (v.startsWith("h:")){ const k = +v.slice(2), x = hosts[k]; if (!x) return;
        return editDevice({name:cleanName(x.name), macs:[lc(x.mac)], ip:x.ip}, d=>{ attach(); S.cfg.dhcp.hosts.splice(S.cfg.dhcp.hosts.indexOf(x),1); S.cfg.devices.push(d); render(); }); }
      const l = cand.find(x=>lc(x.mac)===v); if (!l) return;
      editDevice({name:cleanName(l.name==="*"?"":l.name), macs:[lc(l.mac)]}, d=>{ attach(); S.cfg.devices.push(d); render(); }); }},
      h("option",{value:""},"从终端添加…"),
      cand.length ? h("optgroup",{label:"DHCP 终端"}, cand.map(l=>h("option",{value:lc(l.mac)}, (l.name&&l.name!=="*"?l.name:"未命名")+" · "+l.ip+" · "+lc(l.mac)))) : null,
      hosts.length ? h("optgroup",{label:"静态分配（移入设备清单）"}, hosts.map((x,k)=>h("option",{value:"h:"+k}, (x.name||"未命名")+" · "+x.ip+" · "+lc(x.mac)))) : null);
    const gRows = Object.keys(groups()).sort().map(g=>{
      const members = groups()[g]||[];
      const anyPaused = members.some(n=>((devs().find(d=>d.name===n)||{}).macs||[]).some(m=>paused[lc(m)]));
      return [h("b",{},g), h("span",{class:"row"}, members.map(n=>h("span",{class:"tag"},n))), refsCell(refsOf("group:"+g)),
        h("span",{class:"row",style:"flex-wrap:nowrap"},
          anyPaused ? h("button",{class:"btn sm",onclick:()=>unpause("group:"+g, "分组 "+g)},"恢复") : h("button",{class:"btn sm",onclick:()=>pauseDlg("group:"+g, "分组 "+g, load)},"暂停"),
          h("button",{class:"btn sm",onclick:()=>editGroup(g)},"编辑"), h("button",{class:"btn sm d",onclick:()=>delGroup(g)},"删除"))];
    });
    const pRows = pz.map(p=>[h("b",{}, p.name||"-"), mono(p.mac), p.ref||"-", pauseLeft(p),
      h("button",{class:"btn sm",onclick:()=>unpause(p.mac, p.name||p.mac)},"恢复")]);
    info.textContent = tr(devs().length+" 台设备 · "+Object.keys(groups()).length+" 个分组"+(pz.length ? " · "+pz.length+" 个 MAC 暂停中" : ""));
    body.replaceChildren(...[
      card("设备清单（"+rows.length+"）", h("div",{class:"dev-t"}, roTable(["名称","MAC","IPv4","状态","引用","操作"], rows)), h("span",{class:"row"}, pick,
        h("button",{class:"btn sm p",onclick:()=>editDevice({name:"",macs:[]}, d=>{ attach(); S.cfg.devices.push(d); render(); })},"+ 添加")), true),
      pRows.length ? card("暂停中（"+pRows.length+"）", h("div",{class:"dev-t"}, roTable(["名称","MAC","暂停对象","剩余","操作"], pRows)),
        h("button",{class:"btn sm",onclick:()=>unpause("all","全部")},"全部恢复"), true) : null,
      card("分组（"+gRows.length+"）", h("div",{class:"dev-t"}, roTable(["分组","设备","引用","操作"], gRows)), h("button",{class:"btn sm p",onclick:()=>editGroup("")},"+ 添加"), true),
      card("说明", h("div",{class:"dev-note"},
        "设备 = 一个名字对应一个或多个 MAC（可选固定 IPv4）。端口转发的目标、设备管控、策略路由、代理例外都可以直接写设备名，或 group:分组名；",
        "引用了不存在的名字会在应用前报错。设备的名字就是它的 DHCP / DNS 名，填了固定 IPv4 就是静态分配（和“静态分配”页的旧条目效果相同，同一 MAC 只能在一处）。",
        h("br"), "暂停上网不改配置、没有确认倒计时：只断外网（内网、DHCP、DNS 照常），正在进行的连接立即中断，到时自动恢复；路由器重启也会结束暂停。"), null, true)
    ].filter(Boolean));
  };
  await load();
  return h("div",{}, h("div",{class:"card"}, h("div",{class:"dev-bar"},
      h("input",{type:"search", placeholder:"筛选：名称 / 归属 / MAC / IP", oninput:e=>{ filter = lc(e.target.value.trim()); render(); }}), info,
      h("button",{class:"btn sm",onclick:()=>load().catch(e=>toast(e.message,4000))},"刷新"))), body);
});
})();
