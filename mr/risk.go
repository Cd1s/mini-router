package main

// Risk of a change (Cd1s/mini-router#12 part 2, #38): what it does to the connections through the
// router, and to the administrator's own.
//
//	low     no service restarts (files, an atomic firewall reload)
//	medium  services restart, none on the administrator's own path
//	high    the administrator's path (the service or netdev their session goes through), the LAN
//	        addresses, the WANs, the router's inbound rules / SSH / web UI / tailscale, the guard
//
// The web UI keeps low and medium changes by itself once they are applied, verified and the page
// can still reach the router; a high one waits for 保留 with the reasons in red. `mr apply
// --confirm N --wait` keeps the session in the foreground: y keeps the change, Ctrl-C / a dropped
// SSH connection / the end of the countdown roll it back at once.

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type riskInfo struct {
	Level   string   `json:"level"` // low | medium | high
	Reasons []string `json:"reasons"`
	Effects []string `json:"effects"` // what the plan's actions do, in plain words
}

// adminPath: how the administrator reaches the router — the netdev the route to their address
// uses, and for a bridge the member port (a WiFi interface for a WiFi client).
type adminPath struct {
	Addr string
	Dev  string
	Port string
}

// findAdminPath: addr is the web client's REMOTE_ADDR or the SSH client (SSH_CLIENT's first field).
var findAdminPath = func(addr string) adminPath {
	a := adminPath{Addr: addr}
	if addr == "" {
		return a
	}
	out, err := run("ip", "route", "get", addr)
	if err != nil {
		return a
	}
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			a.Dev = f[i+1]
			break
		}
	}
	if _, err := os.Stat("/sys/class/net/" + a.Dev + "/bridge"); err == nil {
		// the client's MAC, then the bridge port that learned it
		if n, err := run("ip", "neigh", "show", addr, "dev", a.Dev); err == nil {
			if nf := strings.Fields(n); len(nf) > 0 {
				for i := 0; i+1 < len(nf); i++ {
					if nf[i] == "lladdr" {
						if fdb, err := run("bridge", "fdb", "show", "br", a.Dev); err == nil {
							for _, l := range strings.Split(fdb, "\n") {
								if lf := strings.Fields(l); len(lf) >= 3 && strings.EqualFold(lf[0], nf[i+1]) && lf[1] == "dev" {
									a.Port = lf[2]
									break
								}
							}
						}
					}
				}
			}
		}
	}
	return a
}

// sshClientAddr: the address of the SSH client running this command, if any.
func sshClientAddr() string {
	if f := strings.Fields(os.Getenv("SSH_CLIENT")); len(f) > 0 {
		return f[0]
	}
	return ""
}

// serviceEffect: what restarting a service does, in plain words.
func serviceEffect(s string) string {
	switch {
	case s == "mr-hostapd":
		return "WiFi 重启：无线设备断开几秒后自动重连"
	case strings.HasPrefix(s, "mr-pppoe."):
		return "WAN " + strings.TrimPrefix(s, "mr-pppoe.") + " 重新拨号：断网约 5–10 秒，公网地址可能改变"
	case strings.HasPrefix(s, "mr-udhcpc."), s == "mr-dhcpcd":
		return "WAN 重新获取地址：短暂断网"
	case s == "dnsmasq", s == "mr-parental-dns":
		return "DNS / DHCP 重启：解析中断约 1 秒"
	case s == "mr-proxy", s == "mr-proxy-dns":
		return "代理重启：走代理的连接会断开重连"
	case s == "tailscale":
		return "Tailscale 重启：远程访问中断几秒"
	case s == "dropbear":
		return "SSH 服务重启"
	case s == "mr-panel":
		return "网页管理服务重启"
	case s == "mr-edge":
		return "HTTPS 反向代理重启：经它的连接断开重连"
	case s == "mr-network":
		return "网络设置原地重新应用（通常不断线）"
	case s == "hostname", s == "sysctl":
		return "系统参数生效（不断线）"
	}
	return "重启 " + s
}

// classifyRisk rates a plan; changes is its config-level diff (history.go), admin the
// administrator's path (empty when unknown).
func classifyRisk(p *Plan, changes []string, admin adminPath) riskInfo {
	r := riskInfo{Level: "low", Reasons: []string{}, Effects: []string{}}
	high := func(why string) {
		r.Level = "high"
		r.Reasons = append(r.Reasons, why)
	}
	touched := func(prefix string) bool {
		for _, l := range changes {
			if len(l) > 2 && (strings.HasPrefix(l[2:], prefix+".") || strings.HasPrefix(l[2:], prefix+"[") || strings.HasPrefix(l[2:], prefix+":")) {
				return true
			}
		}
		return false
	}
	for _, s := range dedup(append(append([]string{}, p.Services...), p.Enable...)) {
		r.Effects = append(r.Effects, serviceEffect(s))
		if r.Level == "low" {
			r.Level = "medium"
		}
	}
	for _, s := range p.Disable {
		r.Effects = append(r.Effects, "停止 "+s)
		if r.Level == "low" {
			r.Level = "medium"
		}
	}
	if p.Firewall {
		r.Effects = append(r.Effects, "防火墙规则原子替换（不断线）")
	}
	if touched("guard") {
		high("改动了底线（guard）")
	}
	if touched("lan") || touched("networks") {
		high("LAN 地址或网口改变：可能需要到新地址访问")
	}
	if touched("wan") || touched("multiwan") || touched("policy_routes") {
		high("WAN 设置改变")
	}
	for _, s := range p.Services {
		if strings.HasPrefix(s, "mr-pppoe.") || strings.HasPrefix(s, "mr-udhcpc.") || s == "mr-dhcpcd" {
			high("WAN 会断线重连（" + s + "）")
			break
		}
	}
	if touched("firewall.open") || touched("services.ssh") || touched("services.panel") || touched("services.tailscale") {
		high("改动了路由器的入站规则或管理通道（SSH / 网页 / Tailscale）")
	}
	if touched("services.edge") {
		high("改动了 HTTPS 反向代理（对外开放的站点 / 端口）")
	}
	// the administrator's own path
	restarts := map[string]bool{}
	for _, s := range append(append(append([]string{}, p.Services...), p.Enable...), p.Disable...) {
		restarts[s] = true
	}
	switch {
	case admin.Dev == "tailscale0" && restarts["tailscale"]:
		high("你正通过 Tailscale 连接，而 Tailscale 会重启")
	case strings.HasPrefix(admin.Port, "phy") && restarts["mr-hostapd"]:
		high("你正通过 WiFi（" + admin.Port + "）连接，而 WiFi 会重启")
	case strings.HasPrefix(admin.Dev, "pppoe-") && (restarts["mr-pppoe."+strings.TrimPrefix(admin.Dev, "pppoe-")]):
		high("你正从 WAN（" + admin.Dev + "）连接，而这条线路会重拨")
	}
	if os.Getenv("SSH_CLIENT") != "" && restarts["dropbear"] {
		high("你正在用 SSH，而 SSH 服务会重启")
	}
	r.Reasons = dedup(r.Reasons)
	return r
}

// planRisk: the risk of applying c now, for an administrator at addr.
func planRisk(c *Config, p *Plan, addr string) riskInfo {
	changes, known := changesSinceApplied(c)
	r := classifyRisk(p, changes, findAdminPath(addr))
	if !known { // no record of the applied config: nothing above could see what the change touches
		r.Level = "high"
		r.Reasons = append(r.Reasons, "无法判断改动了什么")
	}
	return r
}

func printRisk(r riskInfo, explain bool) {
	fmt.Printf("risk: %s", r.Level)
	if len(r.Reasons) > 0 {
		fmt.Printf(" — %s", strings.Join(r.Reasons, "; "))
	}
	fmt.Println()
	if explain {
		for _, e := range r.Effects {
			fmt.Println("  · " + e)
		}
	}
}

// waitConfirm is `mr apply --confirm N --wait`: the terminal decides. y keeps the change; Ctrl-C, a
// dropped SSH connection (SIGHUP / EOF), or the end of the countdown roll it back at once. The
// detached timer stays armed as the backstop if this process is killed outright.
func waitConfirm(secs int) error {
	p, err := readPending()
	if errors.Is(err, fs.ErrNotExist) || err == nil && p.State != statePending {
		return nil // nothing pending (the apply failed and rolled back, or changed nothing)
	}
	if err != nil {
		return err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGPIPE)
	defer signal.Stop(sig)
	line := make(chan string, 1)
	go func() {
		s, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			s = "\x00eof"
		}
		line <- strings.TrimSpace(s)
	}()
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	fmt.Printf("keep this change? [y/N] (%ds) ", secs)
	for {
		select {
		case s := <-line:
			if strings.EqualFold(s, "y") || strings.EqualFold(s, "yes") {
				if _, err := confirm(); err != nil {
					return err
				}
				fmt.Println("confirmed")
				return nil
			}
			return revertNow("not kept at the prompt")
		case s := <-sig:
			fmt.Println()
			return revertNow("session ended (" + s.String() + ")")
		case <-tick.C:
			left := int(time.Until(deadline).Seconds())
			if left <= 0 {
				fmt.Println()
				return revertNow(fmt.Sprintf("not confirmed within %ds", secs))
			}
			if left%10 == 0 {
				fmt.Printf("\rkeep this change? [y/N] (%ds) ", left)
			}
		}
	}
}

// revertNow rolls the pending change back in this process (what the timer would do later).
func revertNow(why string) error {
	p, ok := startRevert("")
	if !ok {
		return nil
	}
	fmt.Println("rolling back: " + why)
	return rollback(p.Snapshot, errors.New(why))
}
