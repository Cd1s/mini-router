package main

// sys module, DDNS: the providers that only take an address — nothing to read back, so the answer
// says whether anything changed, and a check sends the update again:
//
//   - DuckDNS: GET https://www.duckdns.org/update?domains=<sub>&token=…&ip=…[&ipv6=…]&verbose=true
//     (https://www.duckdns.org/spec.jsp). The token is DuckDNS' own query parameter; it never reaches
//     an error text, a log or the state. A record with both types sends both, so DuckDNS never fills
//     in an address from the connection; an AAAA-only record sends the IPv6 address in ip=.
//   - dyndns2 (No-IP, Dynu, deSEC, …): GET <url>?hostname=<name>&myip=<IPv4>&myipv6=<IPv6> with HTTP basic
//     auth (username + password_secret); answers good / nochg (success), badauth, !donator, nohost,
//     notfqdn, numhost, abuse, badagent, !yours (refused: stop until the config changes), 911 / dnserr
//     (retry later). Fixed extra parameters can stay in the URL (e.g. deSEC's myipv6=preserve for an
//     IPv4-only record).
//   - webhook: GET or POST of an https URL with {name} {type} {ip} {token} placeholders (values
//     URL-escaped); POST also sends {"name","type","ip"} as JSON. A token_secret without {token} in the
//     URL goes into an Authorization: Bearer header. 2xx = done; 401 / 403 = refused. The daily check
//     does not resend it (only changes and 立即更新 do).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var duckAPIBase = "https://www.duckdns.org/update" // a variable so tests use a fake

// ddnsSameIP: a and b are the same address.
func ddnsSameIP(a, b string) bool {
	x := net.ParseIP(a)
	return x != nil && x.Equal(net.ParseIP(b))
}

// ddnsFamilies: the IPv4 and IPv6 address one request of a ddnsBoth provider sends (the updated type
// and, when the record has both, the other one).
func ddnsFamilies(typ, ip string, s *ddnsState) (v4, v6 string) {
	if typ == "AAAA" {
		return s.peer, ip
	}
	return ip, s.peer
}

// ddnsSend makes one request and returns the status and the start of the answer: printable, without
// any form of the secrets, at most 200 bytes.
func ddnsSend(hc *http.Client, req *http.Request, who string, secrets ...string) (int, string, error) {
	req.Header.Set("User-Agent", "mini-router-ddns/"+version)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, "", &ddnsError{msg: who + ": " + ddnsErrText(err, secrets...)}
	}
	defer resp.Body.Close()
	b := ddnsRead(resp)
	if len(b) > 1024 {
		b = b[:1024]
	}
	return resp.StatusCode, ddnsErrText(fmt.Errorf("%s", strings.TrimSpace(string(b))), secrets...), nil
}

func duckUpsert(ctx context.Context, hc *http.Client, token string, r DDNSRecord, typ, ip string, s *ddnsState) (bool, error) {
	sub := strings.TrimSuffix(ddnsName(r.Name), ".duckdns.org")
	q := url.Values{"domains": {sub}, "token": {token}, "verbose": {"true"}}
	if v4, v6 := ddnsFamilies(typ, ip, s); v4 != "" {
		q.Set("ip", v4)
		if v6 != "" {
			q.Set("ipv6", v6)
		}
	} else {
		q.Set("ip", v6) // not ipv6=: an empty ip= makes DuckDNS take IPv4 from the connection
	}
	req, err := http.NewRequestWithContext(ctx, "GET", duckAPIBase+"?"+q.Encode(), nil)
	if err != nil {
		return false, &ddnsError{msg: "DuckDNS: bad request"}
	}
	status, body, err := ddnsSend(hc, req, "DuckDNS", token)
	if err != nil {
		return false, err
	}
	// verbose: OK / KO, the IPv4 and the IPv6 address, UPDATED / NOCHANGE
	f := strings.Fields(body)
	switch {
	case status == 401 || status == 403 || (len(f) > 0 && f[0] == "KO"):
		return false, &ddnsError{msg: "DuckDNS refused the update (KO: wrong token or domain?)", auth: true}
	case status != 200:
		return false, &ddnsError{msg: fmt.Sprintf("DuckDNS: HTTP %d", status)}
	case len(f) == 0 || f[0] != "OK":
		return false, &ddnsError{msg: "DuckDNS: not an update answer"}
	}
	return f[len(f)-1] != "NOCHANGE", nil
}

// dyn2Refused: dyndns2 answers after which retrying cannot help (credentials, host name, blocked client).
var dyn2Refused = map[string]string{
	"badauth": "wrong user name or password", "!donator": "the account does not have this feature", "nohost": "no such host name in the account",
	"notfqdn": "not a host name", "numhost": "too many host names", "abuse": "blocked for abuse", "badagent": "client refused", "!yours": "not your host name",
}

func dyn2Upsert(ctx context.Context, hc *http.Client, pass string, r DDNSRecord, typ, ip string, s *ddnsState) (bool, error) {
	u, err := url.Parse(r.URL)
	if err != nil {
		return false, &ddnsError{msg: "dyndns2: bad URL", auth: true}
	}
	q := u.Query()
	q.Set("hostname", ddnsName(r.Name))
	v4, v6 := ddnsFamilies(typ, ip, s)
	if v4 != "" {
		q.Set("myip", v4)
	}
	if v6 != "" {
		q.Set("myipv6", v6)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return false, &ddnsError{msg: "dyndns2: bad request"}
	}
	req.SetBasicAuth(r.Username, pass)
	status, body, err := ddnsSend(hc, req, "dyndns2", pass)
	if err != nil {
		return false, err
	}
	word := ""
	if f := strings.Fields(body); len(f) > 0 {
		word = strings.ToLower(f[0])
	}
	switch {
	case status == 401 || status == 403 || dyn2Refused[word] != "":
		why := dyn2Refused[word]
		if why == "" {
			why = "credentials refused"
		}
		return false, &ddnsError{msg: fmt.Sprintf("dyndns2 refused the update: HTTP %d %s (%s)", status, eventClean(body, 40), why), auth: true}
	case status == 200 && word == "good":
		return true, nil
	case status == 200 && word == "nochg":
		return false, nil
	}
	return false, &ddnsError{msg: fmt.Sprintf("dyndns2: HTTP %d %s", status, eventClean(body, 60))}
}

// hookURL fills in the webhook's placeholders (URL-escaped values).
func hookURL(raw, name, typ, ip, token string) string {
	return strings.NewReplacer("{name}", url.QueryEscape(name), "{type}", typ, "{ip}", url.QueryEscape(ip), "{token}", url.QueryEscape(token)).Replace(raw)
}

func hookUpsert(ctx context.Context, hc *http.Client, token string, r DDNSRecord, typ, ip string, s *ddnsState) (bool, error) {
	name := ddnsName(r.Name)
	method, u := "GET", hookURL(r.URL, name, typ, ip, token)
	var rd io.Reader
	if r.Method == "POST" {
		b, _ := json.Marshal(map[string]string{"name": name, "type": typ, "ip": ip})
		method, rd = "POST", bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return false, &ddnsError{msg: "webhook: bad URL", auth: true}
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" && !strings.Contains(r.URL, "{token}") {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	status, _, err := ddnsSend(hc, req, "webhook", token)
	switch {
	case err != nil:
		return false, err
	case status == 401 || status == 403:
		return false, &ddnsError{msg: fmt.Sprintf("webhook refused the request: HTTP %d", status), auth: true}
	case status/100 != 2:
		return false, &ddnsError{msg: fmt.Sprintf("webhook: HTTP %d", status)}
	}
	return true, nil
}
