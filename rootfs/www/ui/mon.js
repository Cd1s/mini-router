// mini-router web UI — mon module pages: 实时监控 (realtime + 24 h), 流量统计 (per device), 连接, 进程与内核日志.
// Uses the helpers in ui/core.js; see docs/MODULES.md and docs/modules/mon.md. Read-only: never touches S.cfg.
"use strict";
(()=>{
addCSS(`
.mon-kpi{display:grid;gap:10px;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));margin-bottom:14px}
.mon-kpi .card{margin:0}
.mon-axis{display:flex;justify-content:space-between;font-size:11px;color:var(--mut);padding-left:66px}
.mon-tbl th,.mon-tbl td{padding:5px 8px;font-size:12px;white-space:nowrap}
.mon-tbl td.w{white-space:normal;word-break:break-all;min-width:180px}
.mon-tbl .n{text-align:right;font-variant-numeric:tabular-nums}
.mon-tbl tr.on td{background:rgba(47,111,237,.10)}
.mon-tbl tr.ck{cursor:pointer}
.mon-tbl tr.ck:hover td{background:rgba(47,111,237,.05)}
.mon-sub{display:block;font-size:11px;color:var(--mut);font-weight:400}
.mon-bar{height:3px;background:var(--line);border-radius:2px;margin-top:2px;min-width:50px}
.mon-bar i{display:block;height:100%;background:var(--acc);border-radius:2px}
.mon-filter{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.mon-filter select,.mon-filter input[type=text]{width:auto;min-width:0;max-width:170px}
.mon-chips{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.mon-note{padding:8px 12px;border-radius:6px;background:rgba(201,138,11,.08);border:1px solid rgba(201,138,11,.35);color:var(--warn);margin-bottom:12px;font-size:12px}
.mon-hint{color:var(--mut);font-size:12px;padding:8px 16px}
.mon-grid2{display:grid;gap:0 14px;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));align-items:start}
.mon-log{max-height:70vh;overflow:auto;background:var(--code);border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:12px}
.mon-log div{white-space:pre-wrap;word-break:break-all}
.mon-log .l0,.mon-log .l1,.mon-log .l2,.mon-log .l3{color:var(--bad)}
.mon-log .l4{color:var(--warn)}
.mon-log .l7{color:var(--mut)}
.mon-lbl{font-weight:400;font-size:12px;display:inline-flex;gap:4px;align-items:center;white-space:nowrap}
.mon-stack{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--line)}
.mon-stack i{display:block;height:100%}
.mon-legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12px;color:var(--mut);margin-top:10px}
.mon-legend b{color:var(--fg);font-weight:600;font-variant-numeric:tabular-nums}
.mon-sw{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:-1px;border:1px solid var(--line)}
.mon-core{display:grid;grid-template-columns:40px 1fr 42px;gap:10px;align-items:center;margin:6px 0;font-size:12px}
.mon-core .mon-stack{height:10px}
.mon-core .n{text-align:right;font-variant-numeric:tabular-nums;font-weight:600}
.mon-lbl2{font-size:12px;color:var(--mut);margin-bottom:6px}
.mon-lbl2 b{color:var(--fg)}
.mon-dn{color:${COLORS[0]}}.mon-up{color:${COLORS[1]}}
.mon-wan .spark{height:22px;margin-top:4px}
@media (max-width:820px){.mon-grid2{grid-template-columns:1fr}}
`);

// ---------- shared helpers ----------
const ROLE = {"wan":"WAN","wan-dev":"WAN 物理口","lan":"LAN 网桥","port":"交换口","wifi":"无线","vpn":"VPN"};
const bps = Bps => fmtRate((+Bps||0)*8);                   // API rates are bytes/s
const pct = (a,b) => b>0 ? Math.max(0, Math.min(100, a*100/b)) : 0;
// clock label for unix seconds t; span (s) picks the precision: < 1 h → HH:MM:SS, < 20 h → HH:MM, else MM-DD HH:MM
const clock = (t, span) => { const d = new Date(t*1000), p = n => String(n).padStart(2,"0"), hm = p(d.getHours())+":"+p(d.getMinutes());
  return span < 3600 ? hm+":"+p(d.getSeconds()) : span < 72000 ? hm : p(d.getMonth()+1)+"-"+p(d.getDate())+" "+hm; };
const secs = s => s<0 ? "—" : s<60 ? s+" 秒" : fmtDur(s);
const hostport = (ip, port) => !port ? ip : (ip.includes(":") ? "["+ip+"]:" : ip+":")+port;
const mbar = p => h("div",{class:"mon-bar"}, h("i",{style:"width:"+p.toFixed(0)+"%"}));
const stat = (l, v, sub, p) => h("div",{class:"card stat"}, h("div",{class:"l"},l), h("div",{class:"v"},v), sub?h("div",{class:"s"},sub):null,
  p!==undefined?h("div",{class:"bar"},h("i",{style:"width:"+pct(p,100).toFixed(0)+"%"})):null);
const note = (t, btn) => h("div",{class:"mon-note"+(btn?" row":"")}, btn ? [h("span",{style:"flex:1"}, t), btn] : t);
// mr-mon (re)start also re-applies /etc/sysctl.d/91-mon.conf (conntrack byte accounting)
const monRestart = done => h("button",{class:"btn sm",onclick:async()=>{
  try { await api("service",{name:"mr-mon", op:"restart"}); toast("已重启 mr-mon"); done&&setTimeout(done, 2000); } catch(e){ toast(e.message,4000); } }},"重启 mr-mon");
// put(el, ...kids): replaceChildren without the literal "null" text a real DOM would insert for null kids
const put = (el, ...ks) => el.replaceChildren(...ks.flat(Infinity).filter(k=>k!==null && k!==undefined && k!==false));
const chk = (label, val, on) => h("label",{class:"mon-lbl"}, h("input",{type:"checkbox", checked:!!val, onchange:e=>on(e.target.checked)}), label);
// plain select / text bound to a local (non-config) object: no touch(), no pending bar
const sel = (o, k, opts, on) => h("select",{onchange:e=>{ o[k]=e.target.value; on&&on(); }},
  opts.map(([v,l])=>h("option",{value:v, selected:String(o[k])===String(v)}, l)));
const txt = (o, k, ph, on) => h("input",{type:"text", value:o[k]||"", placeholder:ph, oninput:e=>{ o[k]=e.target.value; },
  onkeydown:e=>{ if(e.key==="Enter"&&on) on(); }});

// tbl(cols, rows): cols = ["标题" | ["标题","n"|"w"]]; rows = [cells] or {c:[cells], cls, on}
function tbl(cols, rows, empty){
  const cc = cols.map(c=>Array.isArray(c)?c:[c,null]);
  return h("div",{class:"tw"}, h("table",{class:"mon-tbl"},
    h("thead",{}, h("tr",{}, cc.map(([l,c])=>h("th",{class:c},l)))),
    h("tbody",{}, rows.length ? rows.map(r=>{ const o = Array.isArray(r)?{c:r}:r;
      return h("tr",{class:o.cls, onclick:o.on}, o.c.map((x,i)=>h("td",{class:cc[i]?cc[i][1]:null}, x))); })
      : h("tr",{}, h("td",{colspan:cc.length, class:"mut"}, empty||"（空）")))));
}

// start(): called first by every page / tab; stops the previous refresh timer and returns here(), which
// stays true only while the user is still on this page and tab (pages call live() after an await).
let gen = 0;
function start(){ clearInterval(S.timer); S.timer = null; const g = ++gen, p = S.page; return ()=>g===gen && S.page===p; }
// live(root, fn, ms, here): run fn every ms while root is on screen (S.timer is cleared on navigation too).
// If the user moved on while the page was loading, S.timer already belongs to the page now on screen.
function live(root, fn, ms, here){
  if (!here()) return;
  clearInterval(S.timer);
  let busy = false;
  const t = setInterval(async ()=>{
    if (!root.isConnected){ clearInterval(t); return; }
    if (busy) return;
    busy = true; try { await fn(); } catch(e){} busy = false;
  }, ms);
  S.timer = t;
}

// chart + time axis (start / middle / end) under it
function chart(series, opts){
  const pts = series.flatMap(s=>s.points);
  if (!pts.length) return lineChart(series, opts);
  const t0 = Math.min(...pts.map(p=>p[0])), t1 = Math.max(...pts.map(p=>p[0])), sp = t1-t0;
  return h("div",{}, lineChart(series, opts), h("div",{class:"mon-axis"}, [t0, (t0+t1)/2, t1].map(t=>h("span",{},clock(t, sp)))));
}

// CPU: fields user nice system idle iowait irq softirq steal (cumulative jiffies)
function cpuPct(a, b){
  if (!a || !b) return null;
  const d = b.map((v,i)=>v-(a[i]||0)), tot = d.reduce((x,y)=>x+y,0);
  if (tot<=0) return null;
  const p = i => d[i]*100/tot;
  return {busy: Math.max(0, 100-p(3)-p(4)), usr: p(0)+p(1), sys: p(2), io: p(4), irq: p(5), sirq: p(6)};
}

// ---------- 实时监控 ----------
const RT = {sel:"", all:false};
const N = 150; // realtime points kept per series (5 min at 2 s)
// CPU time split colours (stacked bars + legend)
const CPUPART = [["usr","用户",COLORS[0]], ["sys","系统",COLORS[4]], ["irq","硬中断",COLORS[3]], ["sirq","软中断",COLORS[5]], ["io","iowait",COLORS[2]]];
const stack = parts => h("div",{class:"mon-stack"}, parts.filter(x=>x[0]>0.05).map(([v,c,t])=>h("i",{style:`width:${Math.min(100,v).toFixed(2)}%;background:${c}`, title:t||""})));
const legend = items => h("div",{class:"mon-legend"}, items.map(([c,l,v])=>h("span",{}, h("span",{class:"mon-sw",style:"background:"+c}), l+" ", h("b",{},v))));
const DISK = {config:"配置存储", tmp:"/tmp（内存盘）"};

async function pageRealtime(){
  const here = start();
  const kpi = h("div",{class:"grid gauges"}), memBox = h("div"), cpuBars = h("div"), cpuChart = h("div");
  const trafTitle = h("span"), trafChart = h("div"), ifTbl = h("div");
  const root = h("div",{}, kpi,
    h("div",{class:"mon-grid2",style:"margin-top:14px"}, card("内存", memBox), card("CPU（每核）", [cpuBars, h("div",{style:"margin-top:12px"}, cpuChart)])),
    card(h("span",{},"接口流量 · ", trafTitle), [trafChart, h("div",{style:"margin-top:10px"}, ifTbl),
      h("div",{class:"mut",style:"font-size:12px;margin-top:8px"},"点击接口切换曲线。已被硬件/软件加速的连接不经过 pppoe-* 等虚拟接口的计数，外网实际流量以「WAN 物理口」为准。")],
      chk("显示空闲接口", RT.all, v=>{ RT.all=v; draw(); })));
  const hist = {}, cpuH = [], kh = {rx:[], tx:[], cpu:[], mem:[], ct:[], temp:[]};
  let prev = null, cur = null;
  const push = (a, v)=>{ if (v==null) return; a.push(v); if (a.length>N) a.shift(); };

  const sample = async ()=>{
    const j = await api("mon.now");
    const m = j.mem||{}, temps = (j.temps||[]).filter(x=>x.mc);
    j.memUsed = (m.total||0)-(m.avail||0);
    j.tmax = temps.length ? Math.max(...temps.map(x=>x.mc))/1000 : null;
    if (prev && j.up > prev.up){
      const dt = j.up - prev.up, t = j.t/1000;
      const pi = Object.fromEntries((prev.ifaces||[]).map(x=>[x.name,x]));
      for (const x of j.ifaces||[]){
        const p = pi[x.name]; if (!p) continue;
        x.rr = x.rx>=p.rx ? (x.rx-p.rx)/dt : 0; x.tr = x.tx>=p.tx ? (x.tx-p.tx)/dt : 0;
        push(hist[x.name] ||= [], [t, x.rr, x.tr]);
      }
      (j.cpus||[]).forEach((c,i)=>{ const u = cpuPct(prev.cpus&&prev.cpus[i], c); if (u){ j["c"+i] = u; push(cpuH[i] ||= [], [t, u.busy]); } });
      j.total = cpuPct(prev.cpu, j.cpu);
      const w = wanOf(j.ifaces||[]);
      push(kh.rx, w.reduce((s,x)=>s+(x.rr||0),0)*8); push(kh.tx, w.reduce((s,x)=>s+(x.tr||0),0)*8);
      push(kh.cpu, j.total && j.total.busy);
    }
    push(kh.mem, m.total ? j.memUsed*100/m.total : null); push(kh.ct, j.ct); push(kh.temp, j.tmax);
    prev = j; cur = j;
    draw();
  };
  const wanOf = ifs => ifs.some(x=>x.role==="wan-dev") ? ifs.filter(x=>x.role==="wan-dev") : ifs.filter(x=>x.role==="wan");

  const draw = ()=>{
    const j = cur; if (!j) return;
    const ifs = j.ifaces||[];
    if (!RT.sel || !ifs.some(x=>x.name===RT.sel)){
      const pick = ifs.find(x=>x.role==="wan-dev") || ifs.find(x=>x.role==="wan") || ifs.find(x=>x.role==="lan") || ifs[0];
      RT.sel = pick ? pick.name : "";
    }
    // gauges
    const wan = wanOf(ifs), known = wan.some(x=>x.rr!==undefined);
    const m = j.mem||{}, tot = j.total, cores = (j.cpus||[]).length;
    const wanCard = h("div",{class:"card gauge mon-wan"}, h("div",{class:"gauge-t"},
      h("div",{class:"l"}, "WAN 实时 · ", wan.map(x=>x.name).join(" + ")||"-"),
      h("div",{class:"v"}, h("span",{class:"mon-dn"},"↓ "), known ? fmtRate(kh.rx[kh.rx.length-1]||0) : "…"),
      h("div",{class:"s"}, h("span",{class:"mon-up"},"↑ "), known ? fmtRate(kh.tx[kh.tx.length-1]||0) : "正在采样…"),
      spark(kh.rx, COLORS[0]), spark(kh.tx, COLORS[1])));
    put(kpi, wanCard,
      gauge({label:"CPU", pct:tot ? tot.busy : null, value:tot ? tot.busy.toFixed(1)+" %" : "…",
        sub:cores+" 核 · 负载 "+(j.load||[]).map(v=>v.toFixed(2)).join(" / "), extra:spark(kh.cpu, null, 100)}),
      gauge({label:"内存", pct:m.total ? j.memUsed*100/m.total : null, value:fmtBytes(j.memUsed*1024),
        sub:"共 "+fmtBytes((m.total||0)*1024)+" · 可用 "+fmtBytes((m.avail||0)*1024), extra:spark(kh.mem, COLORS[4], 100)}),
      gauge({label:"连接数", pct:j.ct_max ? j.ct*100/j.ct_max : null, value:String(j.ct??"-"),
        sub:"上限 "+(j.ct_max??"-")+" · 进程 "+(j.procs??"-"), extra:spark(kh.ct, COLORS[5])}),
      gauge({label:"温度", pct:j.tmax, center:j.tmax==null ? "-" : j.tmax.toFixed(0)+"°", lv:level(j.tmax, 75, 90),
        value:j.tmax==null ? "-" : j.tmax.toFixed(1)+" °C", sub:(j.temps||[]).map(x=>x.type).join(", ")||"无温度传感器", extra:spark(kh.temp, COLORS[3])}),
      (j.disks||[]).map(d=>{ const used = d.total_kb-d.avail_kb;
        return gauge({label:DISK[d.name]||d.path, pct:used*100/d.total_kb, value:fmtBytes(used*1024),
          sub:"共 "+fmtBytes(d.total_kb*1024)+" · 剩余 "+fmtBytes(d.avail_kb*1024)}); }));
    // memory composition: programs / cache / free (of MemTotal), plus zram swap
    if (m.total){
      const cache = (m.buffers||0)+(m.cached||0), prog = Math.max(0, m.total-(m.free||0)-cache), P = v=>v*100/m.total;
      const swapUsed = (m.swap_total||0)-(m.swap_free||0);
      put(memBox, stack([[P(prog),COLORS[0],"程序"], [P(cache),COLORS[5],"缓存"]]),
        legend([[COLORS[0],"程序",fmtBytes(prog*1024)+" · "+P(prog).toFixed(0)+"%"], [COLORS[5],"缓存（可回收）",fmtBytes(cache*1024)],
          ["var(--line)","空闲",fmtBytes((m.free||0)*1024)], ["transparent","可用",fmtBytes((m.avail||0)*1024)]]),
        m.swap_total ? h("div",{style:"margin-top:14px"}, h("div",{class:"mon-lbl2"}, "zram 压缩交换 ", h("b",{}, fmtBytes(swapUsed*1024)+" / "+fmtBytes(m.swap_total*1024))),
          stack([[swapUsed*100/m.swap_total, COLORS[4], "zram"]])) : null,
        h("div",{class:"mon-hint",style:"padding:10px 0 0"}, "“可用”= 程序需要时能拿到的内存（空闲 + 大部分缓存）。缓存是文件读写的加速，内存紧张时内核会自动释放。"));
    }
    // CPU per core: stacked split + history
    const coreRow = (name, u) => h("div",{class:"mon-core"}, h("b",{},name),
      u ? stack(CPUPART.map(([k,l,c])=>[u[k],c,l])) : h("div",{class:"mon-stack"}), h("span",{class:"n"}, u ? u.busy.toFixed(0)+"%" : "…"));
    put(cpuBars, (j.cpus||[]).map((_,i)=>coreRow("CPU"+i, j["c"+i])), tot ? coreRow("合计", tot) : null,
      legend(CPUPART.map(([k,l,c])=>[c, l, tot ? tot[k].toFixed(1)+"%" : "…"])));
    put(cpuChart, cpuH.length ? chart(cpuH.map((a,i)=>({label:"CPU"+i, color:COLORS[i%COLORS.length], points:a})),
      {height:130, max:100, fmt:v=>v.toFixed(0)+"%"}) : h("div",{class:"mut"},"正在采样…"));
    // traffic chart of the selected interface
    const it = ifs.find(x=>x.name===RT.sel), hs = hist[RT.sel]||[];
    put(trafTitle, h("b",{}, RT.sel||"-"), it && it.role ? h("span",{class:"mut"}," （"+ROLE[it.role]+"）") : null);
    put(trafChart, hs.length ? chart([
      {label:"↓ 接收", color:COLORS[0], points:hs.map(p=>[p[0], p[1]*8])},
      {label:"↑ 发送", color:COLORS[1], points:hs.map(p=>[p[0], p[2]*8])}], {height:170, fmt:fmtRate}) : h("div",{class:"mut"},"正在采样…"));
    const rows = ifs.filter(x=>RT.all || x.name===RT.sel || x.rx+x.tx>0).map(x=>({cls:"ck"+(x.name===RT.sel?" on":""), on:()=>{ RT.sel=x.name; draw(); },
      c:[h("b",{},x.name), x.role ? ROLE[x.role] : h("span",{class:"mut"},"-"),
        h("span",{}, h("span",{class:"dot "+(x.state==="down"?"bad":"ok")}), x.state||"-"),
        x.rr!==undefined ? bps(x.rr) : "…", x.tr!==undefined ? bps(x.tr) : "…",
        fmtBytes(x.rx), fmtBytes(x.tx), (x.err||0)+" / "+(x.drop||0)]}));
    put(ifTbl, tbl(["接口","类型","状态",["↓ 接收速率","n"],["↑ 发送速率","n"],["↓ 累计","n"],["↑ 累计","n"],["错误 / 丢弃","n"]], rows));
  };

  await sample();
  live(root, sample, 2000, here);
  setTimeout(()=>{ if (here() && root.isConnected) sample().catch(()=>{}); }, 700); // rates right away, not after 2 s
  return root;
}

// ---------- 24 小时 ----------
const HR = {range:"1440"};

async function pageHistory(){
  const here = start();
  const body = h("div");
  let j = null;
  const load = async ()=>{ j = await api("mon.history"); draw(); };
  const draw = ()=>{
    if (!j) return;
    const from = j.now - Number(HR.range)*60, T = j.t||[];
    const idx = T.map((_,i)=>i).filter(i=>T[i]>=from);
    const col = (k, f)=>idx.filter(i=>j[k][i]!==null && j[k][i]!==undefined).map(i=>[T[i], f ? f(j[k][i]) : j[k][i]]);
    const rx = col("rx", v=>v*8), tx = col("tx", v=>v*8);
    // bytes in range: rate × seconds since the previous sample
    const bytes = k => idx.reduce((s,i)=>s + (i>0 && j[k][i]!==null ? j[k][i]*(T[i]-T[i-1]) : 0), 0);
    const peak = a => a.reduce((m,p)=>Math.max(m,p[1]),0), avg = a => a.length ? a.reduce((s,p)=>s+p[1],0)/a.length : 0;
    const small = (title, series, opts, sub) => card(title, [chart(series, Object.assign({height:120}, opts)), sub ? h("div",{class:"mut",style:"font-size:12px;margin-top:6px"},sub) : null]);
    const cpu = col("cpu"), mem = col("mem", v=>pct(v, j.mem_total)), ct = col("ct"), temp = col("temp");
    put(body, 
      j.collector && j.collector.ok ? null : note("历史采样服务 mr-mon 没有在运行（最后一次采样："+(j.collector && j.collector.age>=0 ? secs(j.collector.age)+"前" : "无")+
        "）。历史只保存在内存里，重启路由器后从零开始，重启服务后 1–2 分钟出第一个点。", monRestart()),
      card("WAN 流量（"+((j.wan||[]).join(" + ")||"-")+"，每分钟平均）", [
        chart([{label:"↓ 下载", color:COLORS[0], points:rx}, {label:"↑ 上传", color:COLORS[1], points:tx}], {height:180, fmt:fmtRate}),
        h("div",{class:"mon-chips",style:"margin-top:8px;font-size:12px"},
          h("span",{class:"tag"},"区间流量 ↓ "+fmtBytes(bytes("rx"))+"  ↑ "+fmtBytes(bytes("tx"))),
          h("span",{class:"tag"},"峰值 ↓ "+fmtRate(peak(rx))+"  ↑ "+fmtRate(peak(tx))),
          h("span",{class:"tag"},"平均 ↓ "+fmtRate(avg(rx))+"  ↑ "+fmtRate(avg(tx))))]),
      h("div",{class:"mon-grid2"},
        small("CPU", [{label:"CPU %", color:COLORS[2], points:cpu}], {max:100, fmt:v=>v.toFixed(0)+"%"}, cpu.length ? "峰值 "+peak(cpu).toFixed(1)+"% · 平均 "+avg(cpu).toFixed(1)+"%" : ""),
        small("内存", [{label:"已用 %", color:COLORS[4], points:mem}], {max:100, fmt:v=>v.toFixed(0)+"%"}, mem.length ? "峰值 "+peak(mem).toFixed(1)+"% · 总内存 "+fmtBytes(j.mem_total*1024) : ""),
        small("连接数", [{label:"conntrack", color:COLORS[5], points:ct}], {fmt:v=>v.toFixed(0)}, ct.length ? "峰值 "+peak(ct) : ""),
        small("温度", [{label:"°C", color:COLORS[3], points:temp}], {fmt:v=>v.toFixed(0)+"°"}, temp.length ? "峰值 "+peak(temp).toFixed(1)+" °C" : "")));
  };
  await load();
  const root = h("div",{}, h("div",{class:"mon-filter",style:"margin-bottom:12px"},
    sel(HR, "range", [["60","最近 1 小时"],["360","最近 6 小时"],["1440","最近 24 小时"]], draw),
    h("button",{class:"btn sm",onclick:()=>load().catch(e=>toast(e.message,4000))},"刷新"),
    h("span",{class:"mut",style:"font-size:12px"},"每分钟一个点，只存在内存中（/run），重启后清空。")), body);
  live(root, load, 60000, here);
  return root;
}

registerPage("status", "mon", "实时监控", 12, ()=>tabs([["rt","实时（2 秒）",pageRealtime], ["24h","24 小时",pageHistory]]));

// ---------- 流量统计（每台设备） ----------
const CF = {proto:"", family:"0", ip:"", port:"", state:"", offload:"", limit:"200", auto:false}; // 连接页过滤条件

registerPage("status", "mon-devices", "流量统计", 22, async ()=>{
  const here = start();
  const notes = h("div"), kpi = h("div",{class:"mon-kpi"}), list = h("div"), meta = h("span",{class:"mut",style:"font-size:12px;font-weight:400"});
  const root = h("div",{}, notes, kpi, card("设备流量", [list,
    h("div",{class:"mon-hint"},"数据来自连接跟踪（conntrack）的字节计数：速率 = 两次刷新之间每条连接的增量；“连接内累计”只含仍在连接表中的连接，不是开机以来的总量。"+
      "硬件加速（PPE/WED）的连接由内核约每秒同步一次计数，数值会滞后 1–2 秒并呈阶梯状。")], meta, true));
  const draw = async ()=>{
    const j = await api("mon.devices");
    const ns = [];
    if (!j.available) ns.push(note("读取不到连接跟踪表（/proc/net/nf_conntrack），无法统计。"));
    if (j.available && !j.acct) ns.push(note("连接字节计数未开启（net.netfilter.nf_conntrack_acct=0）。重启 mr-mon 会重新应用 /etc/sysctl.d/91-mon.conf（从没应用过含 mon 的配置时，先保存并应用一次）；只对之后新建的连接生效。", monRestart()));
    if (j.flowtable && !j.flow_counter) ns.push(note("流表（flow offload）没有开启 counter：连接被硬件/软件加速之后的字节不会计入，设备流量和速率会明显偏低。"));
    if (j.truncated) ns.push(note("连接数过多，只统计了前 "+j.entries+" 条。"));
    put(notes, ...ns);
    const devs = j.devices||[], o = j.other, rated = j.dt>0;
    const all = o ? devs.concat([o]) : devs;
    const sum = k => all.reduce((s,d)=>s+(d[k]||0),0);
    const maxR = Math.max(1, ...all.map(d=>(d.down_rate||0)+(d.up_rate||0)));
    put(kpi, 
      stat("总下载", rated ? bps(sum("down_rate")) : "…", "所有设备 + 路由器自身"),
      stat("总上传", rated ? bps(sum("up_rate")) : "…", rated ? "统计间隔 "+j.dt.toFixed(1)+" 秒" : "首次采样，3 秒后出速率"),
      stat("活跃设备", String(devs.length), "有连接的内网设备"),
      stat("连接数", String(j.entries||0), (j.acct?"字节计数已开启":"字节计数未开启")));
    meta.textContent = tr(rated ? "每 3 秒刷新" : "正在建立基准…");
    const rate = (d,k) => rated ? [bps(d[k]), k==="down_rate" ? mbar(pct((d.down_rate||0)+(d.up_rate||0), maxR)) : null] : "…";
    const row = d => [
      d.id==="other" ? h("span",{class:"mut"},"路由器自身 / 其他", h("span",{class:"mon-sub"},"Tailscale、NTP、DNS 上游等")) :
        [h("b",{}, d.name||"未命名"), h("span",{class:"mon-sub mono"}, d.mac||"MAC 未知")],
      (d.ips||[]).length ? h("span",{class:"mono", title:(d.ips||[]).join("\n")}, d.ips[0], d.ips.length>1 ? h("span",{class:"mut"}," +"+(d.ips.length-1)) : null) : "-",
      rate(d,"down_rate"), rate(d,"up_rate"), String(d.conns),
      fmtBytes(d.down)+" / "+fmtBytes(d.up),
      d.id!=="other" && (d.ips||[]).length ? h("button",{class:"btn sm",onclick:()=>{ Object.assign(CF,{ip:d.ips[0], port:"", proto:"", state:"", offload:""}); location.hash="#mon-conns"; }},"连接") : ""];
    put(list, tbl(["设备","IP",["↓ 下载","n"],["↑ 上传","n"],["连接","n"],["连接内累计 ↓ / ↑","n"],""],
      devs.map(row).concat(o && o.conns ? [row(o)] : []), "没有活动连接"));
  };
  await draw();
  live(root, draw, 3000, here);
  return root;
});

// ---------- 连接 ----------
const TCP_STATES = ["ESTABLISHED","SYN_SENT","SYN_RECV","FIN_WAIT","CLOSE_WAIT","LAST_ACK","TIME_WAIT","CLOSE"];
const PROTO = {tcp:"TCP", udp:"UDP", icmp:"ICMP", icmpv6:"ICMPv6"};

registerPage("status", "mon-conns", "连接", 40, async ()=>{
  const here = start();
  const sum = h("div"), tops = h("div",{class:"mon-grid2"}), list = h("div"), info = h("span",{class:"mut",style:"font-size:12px;font-weight:400"});
  const q = ()=>({proto:CF.proto, family:Number(CF.family)||0, ip:CF.ip.trim(), port:Number(CF.port)||0, state:CF.state, offload:CF.offload, limit:Number(CF.limit)||200});
  let root;
  const load = async ()=>{
    let j;
    try { j = await api("mon.conns", q()); } catch(e){ put(list, h("div",{class:"err",style:"padding:12px 16px"}, "查询失败："+e.message)); return; }
    draw(j);
  };
  const pickIP = ip => { CF.ip = ip; show("mon-conns"); };
  const draw = j => {
    const names = j.names||{}, nm = ip => names[ip] ? h("span",{class:"mon-sub"}, names[ip]) : null;
    const chips = (m, lab) => Object.entries(m||{}).filter(([,n])=>n>0).sort((a,b)=>b[1]-a[1]).map(([k,n])=>h("span",{class:"tag"}, (lab?lab(k):k)+" "+n));
    const off = j.by_offload||{}, fam = j.by_family||{};
    put(sum, 
      j.available ? null : note("读取不到连接跟踪表（/proc/net/nf_conntrack）。"),
      j.truncated ? note("连接过多，只读取了前 "+j.total+" 条。") : null,
      h("div",{class:"mon-chips",style:"margin-bottom:12px"},
        h("b",{style:"font-size:13px"},"共 "+j.total+" 条"), h("span",{class:"mut",style:"font-size:12px"},"（匹配 "+j.matched+"，显示 "+(j.conns||[]).length+"）"),
        chips(j.by_proto, k=>PROTO[k]||k),
        h("span",{class:"tag ok"},"硬件加速 "+(off.hw||0)), h("span",{class:"tag"},"软件加速 "+(off.sw||0)), h("span",{class:"tag"},"未加速 "+(off.none||0)),
        h("span",{class:"tag"},"IPv4 "+(fam["4"]||0)+" / IPv6 "+(fam["6"]||0)),
        chips(j.by_state)));
    const top = (title, arr) => card(title, tbl(["地址",["连接","n"],["流量","n"]], (arr||[]).map(t=>({cls:"ck", on:()=>pickIP(t.ip),
      c:[h("span",{}, h("span",{class:"mono"},t.ip), t.name ? h("span",{class:"mon-sub"},t.name) : null), String(t.conns), fmtBytes(t.bytes)]}))), null, true);
    put(tops, top("发起方 Top 10（按流量）", j.top_src), top("目的地址 Top 10（按流量）", j.top_dst));
    const rows = (j.conns||[]).map(c=>[
      h("span",{}, PROTO[c.p]||c.p, c.f===6 ? h("span",{class:"mut"}," v6") : null),
      h("span",{}, h("span",{class:"mono"}, hostport(c.src, c.sport)), nm(c.src)),
      h("span",{}, h("span",{class:"mono"}, hostport(c.dst, c.dport)+(c.icmp?" type "+c.icmp:"")), nm(c.dst)),
      c.nat_dst ? h("span",{}, h("span",{class:"mono"},"DNAT → "+hostport(c.nat_dst, c.nat_dport)), nm(c.nat_dst)) :
        c.nat_src ? h("span",{class:"mono mut"},"SNAT "+hostport(c.nat_src, c.nat_sport)) : "",
      c.st || (c.unreplied ? "UNREPLIED" : c.assured ? "ASSURED" : ""),
      c.off==="hw" ? h("span",{class:"tag ok"},"硬件") : c.off==="sw" ? h("span",{class:"tag"},"软件") : "",
      fmtBytes(c.ob), fmtBytes(c.rb), secs(c.ttl)]);
    put(list, tbl(["协议","源","目的","NAT","状态","加速",["↑ 发起方发出","n"],["↓ 回复","n"],["剩余","n"]], rows, "没有匹配的连接"),
      j.flowtable && !j.flow_counter ? h("div",{class:"mon-hint"},"流表没有开启 counter：已加速连接的字节数只包含加速之前的部分。") : null);
    info.textContent = tr("更新于 "+clock(Date.now()/1000, 0));
  };
  const bar = h("div",{class:"mon-filter",style:"margin-bottom:12px"},
    sel(CF,"proto",[["","全部协议"],["tcp","TCP"],["udp","UDP"],["icmp","ICMP"],["icmpv6","ICMPv6"],["other","其他协议"]]),
    sel(CF,"family",[["0","IPv4 + IPv6"],["4","仅 IPv4"],["6","仅 IPv6"]]),
    txt(CF,"ip","IP 或网段", load), txt(CF,"port","端口", load),
    sel(CF,"state",[["","全部 TCP 状态"], ...TCP_STATES.map(s=>[s,s])]),
    sel(CF,"offload",[["","全部"],["hw","硬件加速"],["sw","软件加速"],["any","已加速"],["none","未加速"]]),
    sel(CF,"limit",[["100","100 条"],["200","200 条"],["500","500 条"],["1000","1000 条"],["2000","2000 条"]]),
    h("button",{class:"btn sm p",onclick:load},"查询"),
    h("button",{class:"btn sm",onclick:()=>{ Object.assign(CF,{proto:"",family:"0",ip:"",port:"",state:"",offload:""}); show("mon-conns"); }},"清除"),
    chk("自动刷新（5 秒）", CF.auto, v=>{ CF.auto=v; if (v) live(root, load, 5000, here); else { clearInterval(S.timer); S.timer=null; } }));
  root = h("div",{}, bar, sum, tops, card("连接列表（按流量排序）", list, info, true));
  await load();
  if (CF.auto) live(root, load, 5000, here);
  return root;
});

// ---------- 进程与内核日志 ----------
const PS = {sort:"rss", kernel:false};
const DM = {lvl:"7", q:"", rev:true};

async function pageProcs(){
  const here = start();
  const info = h("div",{class:"mut",style:"font-size:12px;margin:0 0 10px"}), list = h("div");
  let prev = {}, prevUp = 0, cur = null;
  const load = async ()=>{
    const j = await api("mon.procs"), dt = j.up - prevUp, hz = j.hz||100, np = {};
    for (const p of j.procs||[]){
      const q = prev[p.pid];
      if (q && q.start===p.start && dt>0) p.pct = Math.max(0, (p.cpu-q.cpu)/hz/dt*100);
      np[p.pid] = {cpu:p.cpu, start:p.start};
    }
    prev = np; prevUp = j.up; cur = j;
    draw();
  };
  const draw = ()=>{
    const j = cur; if (!j) return;
    const ps = (j.procs||[]).filter(p=>PS.kernel || !p.kernel);
    const by = {rss:(a,b)=>b.rss-a.rss || a.pid-b.pid, cpu:(a,b)=>(b.pct||0)-(a.pct||0) || b.cpu-a.cpu, pid:(a,b)=>a.pid-b.pid, name:(a,b)=>a.name.localeCompare(b.name)}[PS.sort];
    ps.sort(by);
    const user = (j.procs||[]).filter(p=>!p.kernel), rss = user.reduce((s,p)=>s+p.rss,0);
    info.textContent = tr("进程 "+user.length+"（另有内核线程 "+((j.procs||[]).length-user.length)+"）· 用户态常驻内存合计 "+fmtBytes(rss*1024)+
      " / 总内存 "+fmtBytes((j.mem_total||0)*1024)+" · CPU% 以单核为 100%，每 3 秒刷新");
    put(list, tbl([["PID","n"],"名称","用户","状态",["CPU%","n"],["内存 RSS","n"],["线程","n"],["命令","w"]], ps.map(p=>[
      String(p.pid), p.kernel ? h("span",{class:"mut"},"["+p.name+"]") : h("b",{},p.name), p.user, p.state,
      p.pct===undefined ? "…" : p.pct.toFixed(1), p.kernel ? "-" : fmtBytes(p.rss*1024), String(p.threads),
      h("span",{class:"mono"}, p.cmd||"")])));
  };
  await load();
  const root = h("div",{}, h("div",{class:"mon-filter",style:"margin-bottom:10px"},
    h("span",{class:"mut",style:"font-size:12px"},"排序"), sel(PS,"sort",[["rss","按内存"],["cpu","按 CPU"],["pid","按 PID"],["name","按名称"]], draw),
    chk("显示内核线程", PS.kernel, v=>{ PS.kernel=v; draw(); })), info, card("进程", list, null, true));
  live(root, load, 3000, here);
  return root;
}

async function pageDmesg(){
  start();
  const box = h("div",{class:"mon-log mono"}), cnt = h("span",{class:"mut",style:"font-size:12px"});
  let j = await api("mon.dmesg");
  const draw = ()=>{
    const k = DM.q.toLowerCase(), max = Number(DM.lvl);
    let ls = (j.lines||[]).filter(([l,t])=>l<=max && (!k || t.toLowerCase().includes(k)));
    cnt.textContent = tr(ls.length+" / "+(j.lines||[]).length+" 行");
    if (DM.rev) ls = ls.slice().reverse();
    put(box, ...ls.map(([l,t])=>h("div",{class:"l"+l}, t)));
  };
  const reload = async ()=>{ try { j = await api("mon.dmesg"); draw(); } catch(e){ toast(e.message,4000); } };
  const q = h("input",{type:"text", placeholder:"过滤关键字", value:DM.q, oninput:e=>{ DM.q=e.target.value; draw(); }});
  draw();
  return h("div",{}, h("div",{class:"mon-filter",style:"margin-bottom:10px"},
    sel(DM,"lvl",[["7","全部级别"],["5","notice 及以上"],["4","warning 及以上"],["3","error 及以上"]], draw), q,
    chk("新的在上", DM.rev, v=>{ DM.rev=v; draw(); }), h("button",{class:"btn sm",onclick:reload},"刷新"), cnt),
    box, h("div",{class:"mut",style:"font-size:12px;margin-top:6px"},"内核环形缓冲区（dmesg），时间为开机后的秒数。红色 = error 及以上，黄色 = warning。"));
}

registerPage("status", "mon-sys", "进程与内核日志", 50, ()=>tabs([["procs","进程",pageProcs], ["dmesg","内核日志 (dmesg)",pageDmesg]]));
})();
