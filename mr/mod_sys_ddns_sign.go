package main

// sys module, DDNS: the providers with signed APIs, for DDNS records (A / AAAA) and ACME DNS-01 (TXT):
//
//   - AliDNS — Alibaba Cloud DNS, API 2015-01-09 at https://alidns.aliyuncs.com (RPC style: POST with the
//     parameters in the query string), signature ACS3-HMAC-SHA256 (V3). Credentials: AccessKey ID +
//     AccessKey secret (a RAM user with AliyunDNSFullAccess, or a policy for the domain). Records:
//     DescribeSubDomainRecords / UpdateDomainRecord / AddDomainRecord; DNS-01: GetMainDomainName,
//     AddDomainRecord, DeleteDomainRecord.
//   - DNSPod — Tencent Cloud API 3.0, version 2021-03-23 at https://dnspod.tencentcloudapi.com (POST,
//     JSON), signature TC3-HMAC-SHA256. Credentials: SecretId + SecretKey (a CAM sub-user with
//     QcloudDNSPodFullAccess). Records: DescribeRecordList / ModifyRecord / CreateRecord; DNS-01:
//     DescribeDomainList, CreateRecord, DeleteRecord.
//
// Both keep what the owner set on existing records — line (线路), TTL unless configured, status,
// weight — and change only the value; a missing record is created on the default line. The secret
// only enters the HMAC; the request carries the key id and the signature. Answers are capped
// (ddnsMaxBody), ids from answers must be digits before they are sent back.
//
// The signatures follow the providers' documents and are tested against their worked examples
// (mod_sys_ddns_sign_test.go):
//   - ACS3: https://help.aliyun.com/zh/sdk/product-overview/v3-request-structure-and-signature
//     (RunInstances, AccessKey secret "YourAccessKeySecret" → 06563a9e…)
//   - TC3:  https://cloud.tencent.com/document/api/1427/56189 (DNSPod 签名方法 v3; the example is CVM
//     DescribeInstances at 1551113065 → 10b1a37a…)

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// endpoints and the nonce (variables so tests use fake APIs and fixed values)
var (
	aliAPIBase = "https://alidns.aliyuncs.com"
	tcAPIBase  = "https://dnspod.tencentcloudapi.com"
	ddnsNonce  = func() string {
		b := make([]byte, 16)
		rand.Read(b)
		return hex.EncodeToString(b)
	}
)

var reDDNSNumID = lazyRegexp(`^[0-9]{1,20}$`)

// ddnsID: a record id that a provider sends as a JSON number or string; ok() only for digits.
type ddnsID string

func (d *ddnsID) UnmarshalJSON(b []byte) error {
	*d = ddnsID(strings.Trim(string(b), `"`))
	return nil
}

func (d ddnsID) ok() bool { return reDDNSNumID.MatchString(string(d)) }

// ddnsRR: the host part of name inside zone ("@" for the zone itself, "*" for *.zone).
func ddnsRR(name, zone string) string {
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// ---- AliDNS: ACS3-HMAC-SHA256 ----

// rfc3986: ACS3's percent-encoding: A-Z a-z 0-9 - _ . ~ stay, every other byte is %XX (upper case).
func rfc3986(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// acs3Query: the canonical query string — parameters sorted by name, names and values encoded.
func acs3Query(p map[string]string) string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = rfc3986(k) + "=" + rfc3986(p[k])
	}
	return strings.Join(parts, "&")
}

// acs3Auth: the Authorization header of a request to "/" with the canonical query string query, the
// signed headers hdr (lower-case names: host, x-acs-*, content-type; x-acs-content-sha256 = the hex
// SHA-256 of body) and body.
func acs3Auth(keyID, secret, method, query string, hdr map[string]string, body []byte) string {
	names := make([]string, 0, len(hdr))
	for k := range hdr {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + strings.TrimSpace(hdr[n]) + "\n")
	}
	signed := strings.Join(names, ";")
	canon := method + "\n/\n" + query + "\n" + ch.String() + "\n" + signed + "\n" + hexSHA256(body)
	sig := hex.EncodeToString(hmacSHA256([]byte(secret), "ACS3-HMAC-SHA256\n"+hexSHA256([]byte(canon))))
	return "ACS3-HMAC-SHA256 Credential=" + keyID + ",SignedHeaders=" + signed + ",Signature=" + sig
}

// aliAuthCode: error codes that mean the key was refused (retrying cannot help).
func aliAuthCode(code string) bool {
	for _, p := range []string{"InvalidAccessKeyId", "InvalidAccessKeySecret", "SignatureDoesNotMatch", "IncompleteSignature", "Forbidden", "NoPermission"} {
		if strings.HasPrefix(code, p) {
			return true
		}
	}
	return false
}

// aliCall makes one AliDNS API call (POST, parameters in the query string, empty body); out receives
// the answer.
func aliCall(ctx context.Context, hc *http.Client, keyID, secret, action string, params map[string]string, out any) error {
	u, err := url.Parse(aliAPIBase)
	if err != nil || u.Host == "" {
		return &ddnsError{msg: "AliDNS: bad endpoint"}
	}
	q := acs3Query(params)
	hdr := map[string]string{
		"host":                  u.Host,
		"x-acs-action":          action,
		"x-acs-version":         "2015-01-09",
		"x-acs-date":            ddnsNow().UTC().Format("2006-01-02T15:04:05Z"),
		"x-acs-signature-nonce": ddnsNonce(),
		"x-acs-content-sha256":  hexSHA256(nil),
	}
	req, err := http.NewRequestWithContext(ctx, "POST", aliAPIBase+"/?"+q, nil)
	if err != nil {
		return &ddnsError{msg: "AliDNS: bad request"}
	}
	for k, v := range hdr {
		if k != "host" {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Authorization", acs3Auth(keyID, secret, "POST", q, hdr, nil))
	req.Header.Set("User-Agent", "mini-router-ddns/"+version)
	resp, err := hc.Do(req)
	if err != nil {
		return &ddnsError{msg: "AliDNS: " + ddnsErrText(err)}
	}
	defer resp.Body.Close()
	raw := ddnsRead(resp)
	var e struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	jerr := json.Unmarshal(raw, &e)
	why := ""
	if e.Code != "" {
		why = " (" + ddnsErrText(fmt.Errorf("%s: %s", e.Code, e.Message)) + ")"
	}
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403 || aliAuthCode(e.Code):
		return &ddnsError{msg: fmt.Sprintf("AliDNS refused the key: HTTP %d%s", resp.StatusCode, why), auth: true, code: e.Code}
	case jerr != nil:
		return &ddnsError{msg: fmt.Sprintf("AliDNS: HTTP %d, not an API answer", resp.StatusCode)}
	case resp.StatusCode/100 != 2 || e.Code != "":
		return &ddnsError{msg: fmt.Sprintf("AliDNS: HTTP %d%s", resp.StatusCode, why), code: e.Code}
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return &ddnsError{msg: "AliDNS: unexpected answer"}
	}
	return nil
}

type aliRecord struct {
	RecordID ddnsID `json:"RecordId"`
	RR       string `json:"RR"`
	Type     string `json:"Type"`
	Value    string `json:"Value"`
	TTL      int    `json:"TTL"`
	Line     string `json:"Line"`
	Locked   bool   `json:"Locked"`
}

// aliUpsert makes every typ record of r.Name hold ip (its line and TTL stay unless ttl is set), or
// adds one on the default line.
func aliUpsert(ctx context.Context, hc *http.Client, secret string, r DDNSRecord, typ, ip string, s *ddnsState) (bool, error) {
	name, zone := ddnsName(r.Name), ddnsName(r.Zone)
	rr := ddnsRR(name, zone)
	var list struct {
		DomainRecords struct {
			Record []aliRecord `json:"Record"`
		} `json:"DomainRecords"`
	}
	params := map[string]string{"DomainName": zone, "SubDomain": name, "Type": typ, "PageSize": "100"}
	if err := aliCall(ctx, hc, r.KeyID, secret, "DescribeSubDomainRecords", params, &list); err != nil {
		return false, err
	}
	var mine []aliRecord
	for _, x := range list.DomainRecords.Record {
		if strings.EqualFold(x.RR, rr) && x.Type == typ && x.RecordID.ok() {
			mine = append(mine, x)
		}
	}
	if len(mine) == 0 {
		add := map[string]string{"DomainName": zone, "RR": rr, "Type": typ, "Value": ip}
		if r.TTL != 0 {
			add["TTL"] = strconv.Itoa(r.TTL)
		}
		return true, aliCall(ctx, hc, r.KeyID, secret, "AddDomainRecord", add, nil)
	}
	changed := false
	for _, x := range mine {
		ttl := r.TTL
		if ttl == 0 {
			ttl = x.TTL
		}
		if ddnsSameIP(x.Value, ip) && x.TTL == ttl {
			continue
		}
		if x.Locked {
			return changed, &ddnsError{msg: "AliDNS: the record " + name + " " + typ + " is locked"}
		}
		upd := map[string]string{"RecordId": string(x.RecordID), "RR": x.RR, "Type": typ, "Value": ip}
		if ttl > 0 {
			upd["TTL"] = strconv.Itoa(ttl)
		}
		if x.Line != "" {
			upd["Line"] = x.Line
		}
		if err := aliCall(ctx, hc, r.KeyID, secret, "UpdateDomainRecord", upd, nil); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// aliDNS01: ACME TXT records through AliDNS (the zone from GetMainDomainName).
type aliDNS01 struct {
	hc            *http.Client
	keyID, secret string
}

func (p *aliDNS01) present(ctx context.Context, name, value string) (func(context.Context), error) {
	var m struct {
		DomainName string `json:"DomainName"`
		RR         string `json:"RR"`
	}
	if err := aliCall(ctx, p.hc, p.keyID, p.secret, "GetMainDomainName", map[string]string{"InputString": name}, &m); err != nil {
		return nil, err
	}
	zone := ddnsName(m.DomainName)
	if !validDNSName(zone) || !strings.HasSuffix(name, "."+zone) || m.RR != ddnsRR(name, zone) {
		return nil, &ddnsError{msg: "AliDNS: no zone for " + name}
	}
	var add struct {
		RecordID ddnsID `json:"RecordId"`
	}
	params := map[string]string{"DomainName": zone, "RR": m.RR, "Type": "TXT", "Value": value, "TTL": "600"}
	if err := aliCall(ctx, p.hc, p.keyID, p.secret, "AddDomainRecord", params, &add); err != nil {
		return nil, err
	}
	if !add.RecordID.ok() {
		return nil, &ddnsError{msg: "AliDNS: unexpected answer"}
	}
	return func(ctx context.Context) {
		if err := aliCall(ctx, p.hc, p.keyID, p.secret, "DeleteDomainRecord", map[string]string{"RecordId": string(add.RecordID)}, nil); err != nil {
			logf("edge: could not delete the TXT record %s: %s", name, ddnsErrText(err, p.secret))
		}
	}, nil
}

// ---- DNSPod: TC3-HMAC-SHA256 ----

// tc3Auth: the Authorization header of a POST to "/" with a JSON body, signing content-type, host and
// x-tc-action (the headers tcCall sends).
func tc3Auth(id, key, service, host, action string, ts int64, body []byte) string {
	date := time.Unix(ts, 0).UTC().Format("2006-01-02")
	scope := date + "/" + service + "/tc3_request"
	canon := "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:" + host + "\nx-tc-action:" + strings.ToLower(action) +
		"\n\ncontent-type;host;x-tc-action\n" + hexSHA256(body)
	sts := "TC3-HMAC-SHA256\n" + strconv.FormatInt(ts, 10) + "\n" + scope + "\n" + hexSHA256([]byte(canon))
	k := hmacSHA256([]byte("TC3"+key), date)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "tc3_request")
	return "TC3-HMAC-SHA256 Credential=" + id + "/" + scope + ", SignedHeaders=content-type;host;x-tc-action, Signature=" +
		hex.EncodeToString(hmacSHA256(k, sts))
}

// tcAuthCode: error codes that mean the key was refused (a clock that is off is not: SignatureExpire).
func tcAuthCode(code string) bool {
	return (strings.HasPrefix(code, "AuthFailure") && code != "AuthFailure.SignatureExpire") || strings.HasPrefix(code, "UnauthorizedOperation")
}

// tcCall makes one DNSPod API call; out receives "Response".
func tcCall(ctx context.Context, hc *http.Client, id, key, action string, params map[string]any, out any) error {
	u, err := url.Parse(tcAPIBase)
	if err != nil || u.Host == "" {
		return &ddnsError{msg: "DNSPod: bad endpoint"}
	}
	body, _ := json.Marshal(params)
	ts := ddnsNow().Unix()
	req, err := http.NewRequestWithContext(ctx, "POST", tcAPIBase+"/", bytes.NewReader(body))
	if err != nil {
		return &ddnsError{msg: "DNSPod: bad request"}
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-TC-Version", "2021-03-23")
	req.Header.Set("Authorization", tc3Auth(id, key, "dnspod", u.Host, action, ts, body))
	req.Header.Set("User-Agent", "mini-router-ddns/"+version)
	resp, err := hc.Do(req)
	if err != nil {
		return &ddnsError{msg: "DNSPod: " + ddnsErrText(err)}
	}
	defer resp.Body.Close()
	raw := ddnsRead(resp)
	var env struct {
		Response json.RawMessage `json:"Response"`
	}
	var e struct {
		Error *struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
	}
	jerr := json.Unmarshal(raw, &env)
	if jerr == nil {
		jerr = json.Unmarshal(env.Response, &e)
	}
	code, why := "", ""
	if e.Error != nil {
		code = e.Error.Code
		why = " (" + ddnsErrText(fmt.Errorf("%s: %s", e.Error.Code, e.Error.Message)) + ")"
	}
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403 || tcAuthCode(code):
		return &ddnsError{msg: fmt.Sprintf("DNSPod refused the key: HTTP %d%s", resp.StatusCode, why), auth: true, code: code}
	case jerr != nil:
		return &ddnsError{msg: fmt.Sprintf("DNSPod: HTTP %d, not an API answer", resp.StatusCode)}
	case resp.StatusCode/100 != 2 || code != "":
		return &ddnsError{msg: fmt.Sprintf("DNSPod: HTTP %d%s", resp.StatusCode, why), code: code}
	}
	if out != nil && json.Unmarshal(env.Response, out) != nil {
		return &ddnsError{msg: "DNSPod: unexpected answer"}
	}
	return nil
}

type tcRecord struct {
	RecordID ddnsID `json:"RecordId"`
	Name     string `json:"Name"`
	Type     string `json:"Type"`
	Value    string `json:"Value"`
	Line     string `json:"Line"`
	LineID   string `json:"LineId"`
	TTL      int    `json:"TTL"`
	Status   string `json:"Status"`
	Weight   *int   `json:"Weight"`
}

// tcUpsert makes every typ record of r.Name hold ip (line, TTL unless ttl is set, status and weight
// stay), or creates one on the default line.
func tcUpsert(ctx context.Context, hc *http.Client, key string, r DDNSRecord, typ, ip string, s *ddnsState) (bool, error) {
	name, zone := ddnsName(r.Name), ddnsName(r.Zone)
	sub := ddnsRR(name, zone)
	var list struct {
		RecordList []tcRecord `json:"RecordList"`
	}
	q := map[string]any{"Domain": zone, "SubDomain": sub, "RecordType": typ, "Limit": 100, "ErrorOnEmpty": "no"}
	if err := tcCall(ctx, hc, r.KeyID, key, "DescribeRecordList", q, &list); err != nil && !ddnsCode(err, "ResourceNotFound.NoDataOfRecord") {
		return false, err
	}
	var mine []tcRecord
	for _, x := range list.RecordList {
		if strings.EqualFold(x.Name, sub) && x.Type == typ && x.RecordID.ok() {
			mine = append(mine, x)
		}
	}
	if len(mine) == 0 {
		add := map[string]any{"Domain": zone, "SubDomain": sub, "RecordType": typ, "RecordLine": "默认", "RecordLineId": "0", "Value": ip} // i18n-ignore (the default line)
		if r.TTL != 0 {
			add["TTL"] = r.TTL
		}
		return true, tcCall(ctx, hc, r.KeyID, key, "CreateRecord", add, nil)
	}
	changed := false
	for _, x := range mine {
		ttl := r.TTL
		if ttl == 0 {
			ttl = x.TTL
		}
		if ddnsSameIP(x.Value, ip) && x.TTL == ttl {
			continue
		}
		upd := map[string]any{"Domain": zone, "SubDomain": x.Name, "RecordType": typ, "RecordLine": x.Line, "Value": ip, "RecordId": json.Number(x.RecordID)}
		if x.LineID != "" {
			upd["RecordLineId"] = x.LineID
		}
		if ttl > 0 {
			upd["TTL"] = ttl
		}
		if x.Status == "ENABLE" || x.Status == "DISABLE" {
			upd["Status"] = x.Status
		}
		if x.Weight != nil {
			upd["Weight"] = *x.Weight
		}
		if err := tcCall(ctx, hc, r.KeyID, key, "ModifyRecord", upd, nil); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// tcDNS01: ACME TXT records through DNSPod (the zone: the longest of the account's domains that the
// name ends in).
type tcDNS01 struct {
	hc      *http.Client
	id, key string
	domains []string
}

func (p *tcDNS01) present(ctx context.Context, name, value string) (func(context.Context), error) {
	if p.domains == nil {
		var dl struct {
			DomainList []struct {
				Name string `json:"Name"`
			} `json:"DomainList"`
		}
		if err := tcCall(ctx, p.hc, p.id, p.key, "DescribeDomainList", map[string]any{"Limit": 3000}, &dl); err != nil && !ddnsCode(err, "ResourceNotFound.NoDataOfDomain") {
			return nil, err
		}
		p.domains = []string{}
		for _, d := range dl.DomainList {
			p.domains = append(p.domains, ddnsName(d.Name))
		}
	}
	zone := ""
	for _, d := range p.domains {
		if strings.HasSuffix(name, "."+d) && len(d) > len(zone) && validDNSName(d) {
			zone = d
		}
	}
	if zone == "" {
		return nil, &ddnsError{msg: "DNSPod: no domain of the account holds " + name}
	}
	var add struct {
		RecordID ddnsID `json:"RecordId"`
	}
	params := map[string]any{"Domain": zone, "SubDomain": ddnsRR(name, zone), "RecordType": "TXT", "RecordLine": "默认", "RecordLineId": "0", "Value": value, "TTL": 600} // i18n-ignore
	if err := tcCall(ctx, p.hc, p.id, p.key, "CreateRecord", params, &add); err != nil {
		return nil, err
	}
	if !add.RecordID.ok() {
		return nil, &ddnsError{msg: "DNSPod: unexpected answer"}
	}
	return func(ctx context.Context) {
		if err := tcCall(ctx, p.hc, p.id, p.key, "DeleteRecord", map[string]any{"Domain": zone, "RecordId": json.Number(add.RecordID)}, nil); err != nil {
			logf("edge: could not delete the TXT record %s: %s", name, ddnsErrText(err, p.key))
		}
	}, nil
}
