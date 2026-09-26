package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	aliTestID     = "LTAI0000testkey00000"
	aliTestSecret = "ali-test-secret-0123456789abcd"
	tcTestID      = "AKIDtest00000000000000000000000000000"
	tcTestKey     = "tc-test-secret-key-0123456789abcd"
)

// The signatures against the worked examples in the providers' documents.
func TestDDNSSignatureVectors(t *testing.T) {
	// Alibaba Cloud, "V3 版本请求体&签名机制"
	// (https://help.aliyun.com/zh/sdk/product-overview/v3-request-structure-and-signature): ECS RunInstances
	// with AccessKey ID "YourAccessKeyId" and secret "YourAccessKeySecret".
	q := acs3Query(map[string]string{"RegionId": "cn-shanghai", "ImageId": "win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd"})
	if q != "ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai" {
		t.Errorf("ACS3 canonical query: %s", q)
	}
	hdr := map[string]string{
		"host": "ecs.cn-shanghai.aliyuncs.com", "x-acs-action": "RunInstances",
		"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-acs-date": "2023-10-26T10:22:32Z",
		"x-acs-signature-nonce": "3156853299f313e23d1673dc12e1703d", "x-acs-version": "2014-05-26",
	}
	if hexSHA256(nil) != hdr["x-acs-content-sha256"] {
		t.Error("hash of the empty body")
	}
	want := "ACS3-HMAC-SHA256 Credential=YourAccessKeyId,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version," +
		"Signature=06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0"
	if got := acs3Auth("YourAccessKeyId", "YourAccessKeySecret", "POST", q, hdr, nil); got != want {
		t.Errorf("ACS3 example:\n got %s\nwant %s", got, want)
	}
	// the document's encoding rules: space %20, * %2A, ~ stays; UTF-8 bytes
	for in, out := range map[string]string{"a b": "a%20b", "*": "%2A", "~-_.": "~-_.", "默认": "%E9%BB%98%E8%AE%A4", "a+b/c=&": "a%2Bb%2Fc%3D%26"} {
		if got := rfc3986(in); got != out {
			t.Errorf("rfc3986(%q) = %q, want %q", in, got, out)
		}
	}

	// Tencent Cloud API 3.0, "签名方法 v3" (https://cloud.tencent.com/document/api/1427/56189): CVM
	// DescribeInstances at 1551113065; the document masks SecretId / SecretKey as AKID + 32 '*' / 32 '*'
	// and its values are computed with exactly those strings.
	id, key := "AKID"+strings.Repeat("*", 32), strings.Repeat("*", 32)
	body := `{"Limit": 1, "Filters": [{"Values": ["` + "\x5cu672a\x5cu547d\x5cu540d" + `"], "Name": "instance-name"}]}` // the document escapes 未命名
	if h := hexSHA256([]byte(body)); h != "35e9c5b0e3ae67532d3c9f17ead6c90222632e5b1ff7f6e89887f1398934f064" {
		t.Errorf("TC3 payload hash %s", h)
	}
	k1 := hmacSHA256([]byte("TC3"+key), "2019-02-25")
	k2 := hmacSHA256(k1, "cvm")
	k3 := hmacSHA256(k2, "tc3_request")
	for i, w := range []string{"da98fb70dcf6b112dc21038d1eeeb3a95c74b4dcb12c1131f864f6066bd02be0", "8d70cbefb03939f929db64d32dc2ba89b1095620119fe3e050e2b18c5bd2752f",
		"b596b923aad85185e2d1f6659d2a062e0a86731226e021e61bfe06f7ed05f5af"} {
		if g := hex.EncodeToString([][]byte{k1, k2, k3}[i]); g != w {
			t.Errorf("TC3 derived key %d: %s", i+1, g)
		}
	}
	want = "TC3-HMAC-SHA256 Credential=AKID********************************/2019-02-25/cvm/tc3_request, SignedHeaders=content-type;host;x-tc-action, " +
		"Signature=10b1a37a7301a02ca19a647ad722d5e43b4b3cff309d421d85b46093f6ab6c4f"
	if got := tc3Auth(id, key, "cvm", "cvm.tencentcloudapi.com", "DescribeInstances", 1551113065, []byte(body)); got != want {
		t.Errorf("TC3 example:\n got %s\nwant %s", got, want)
	}
	// the date is UTC: 1551113065 is 2019-02-26 00:44 in UTC+8
	if !strings.Contains(tc3Auth(id, key, "dnspod", "h", "A", 1551113065, nil), "/2019-02-25/dnspod/") {
		t.Error("TC3 date not UTC")
	}
}

// fakeAli is a small AliDNS: it checks every request's ACS3 signature and serves the record calls.
type fakeAli struct {
	mu     sync.Mutex
	recs   []map[string]any // RecordId (string, as AliDNS sends it), DomainName, RR, Type, Value, TTL, Line, Locked
	calls  []string
	params []map[string]string
	status int    // answer every call with this HTTP status ...
	code   string // ... and error code
	seq    int
	leak   bool // the secret appeared in a request
}

func (f *fakeAli) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if strings.Contains(r.URL.String()+fmt.Sprint(r.Header)+string(body), aliTestSecret) {
		f.leak = true
	}
	answer := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
	fail := func(status int, code string) {
		answer(status, map[string]any{"RequestId": "req", "HostId": "alidns.aliyuncs.com", "Code": code, "Message": "simulated " + code})
	}
	action := r.Header.Get("x-acs-action")
	f.calls = append(f.calls, action)
	vals, _ := url.ParseQuery(r.URL.RawQuery)
	p := map[string]string{}
	for k := range vals {
		p[k] = vals.Get(k)
	}
	f.params = append(f.params, p)
	hdr := map[string]string{"host": r.Host}
	for k := range r.Header {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-acs-") {
			hdr[lk] = r.Header.Get(k)
		}
	}
	switch {
	case r.Method != "POST" || r.URL.Path != "/" || len(body) != 0 || acs3Query(p) != r.URL.RawQuery:
		fail(400, "InvalidParameter")
		return
	case hdr["x-acs-version"] != "2015-01-09" || hdr["x-acs-content-sha256"] != hexSHA256(nil) || len(hdr["x-acs-signature-nonce"]) != 32 ||
		hdr["x-acs-date"] != ddnsNow().UTC().Format("2006-01-02T15:04:05Z"):
		fail(400, "MissingParameter")
		return
	case !strings.HasPrefix(r.Header.Get("Authorization"), "ACS3-HMAC-SHA256 Credential="+aliTestID+","):
		fail(404, "InvalidAccessKeyId.NotFound")
		return
	case r.Header.Get("Authorization") != acs3Auth(aliTestID, aliTestSecret, "POST", r.URL.RawQuery, hdr, nil):
		fail(400, "SignatureDoesNotMatch")
		return
	case f.status != 0:
		fail(f.status, f.code)
		return
	}
	full := func(x map[string]any) string {
		if x["RR"] == "@" {
			return x["DomainName"].(string)
		}
		return x["RR"].(string) + "." + x["DomainName"].(string)
	}
	switch action {
	case "DescribeSubDomainRecords":
		out := []any{}
		for _, x := range f.recs {
			if full(x) == p["SubDomain"] && x["DomainName"] == p["DomainName"] && x["Type"] == p["Type"] {
				out = append(out, x)
			}
		}
		answer(200, map[string]any{"RequestId": "req", "TotalCount": len(out), "PageSize": 100, "PageNumber": 1, "DomainRecords": map[string]any{"Record": out}})
	case "AddDomainRecord":
		f.seq++
		id := strconv.Itoa(9000 + f.seq)
		x := map[string]any{"RecordId": id, "DomainName": p["DomainName"], "RR": p["RR"], "Type": p["Type"], "Value": p["Value"], "TTL": 600, "Line": "default", "Locked": false}
		if p["TTL"] != "" {
			x["TTL"] = atoi(p["TTL"])
		}
		f.recs = append(f.recs, x)
		answer(200, map[string]any{"RequestId": "req", "RecordId": id})
	case "UpdateDomainRecord":
		for _, x := range f.recs {
			if x["RecordId"] == p["RecordId"] {
				x["RR"], x["Type"], x["Value"] = p["RR"], p["Type"], p["Value"]
				x["TTL"] = 600 // AliDNS: TTL left out = 600
				if p["TTL"] != "" {
					x["TTL"] = atoi(p["TTL"])
				}
				x["Line"] = "default"
				if p["Line"] != "" {
					x["Line"] = p["Line"]
				}
				answer(200, map[string]any{"RequestId": "req", "RecordId": p["RecordId"]})
				return
			}
		}
		fail(400, "DomainRecordNotBelongToUser")
	case "GetMainDomainName":
		l := strings.Split(p["InputString"], ".")
		main := strings.Join(l[len(l)-2:], ".")
		answer(200, map[string]any{"RequestId": "req", "DomainName": main, "RR": strings.TrimSuffix(p["InputString"], "."+main), "DomainLevel": len(l) - 1})
	case "DeleteDomainRecord":
		for i, x := range f.recs {
			if x["RecordId"] == p["RecordId"] {
				f.recs = append(f.recs[:i], f.recs[i+1:]...)
				answer(200, map[string]any{"RequestId": "req", "RecordId": p["RecordId"]})
				return
			}
		}
		fail(400, "DomainRecordNotBelongToUser")
	default:
		fail(400, "InvalidAction.NotFound")
	}
}

func (f *fakeAli) take() ([]string, []map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, p := f.calls, f.params
	f.calls, f.params = nil, nil
	return c, p
}

// fakeTC is a small DNSPod (API 3.0): it checks every request's TC3 signature and serves the record calls.
type fakeTC struct {
	mu      sync.Mutex
	recs    []map[string]any // RecordId (number), Domain, Name, Type, Value, Line, LineId, TTL, Status, Weight
	domains []string
	calls   []string
	bodies  []map[string]any
	code    string // answer every call with this error code
	seq     int
	leak    bool
}

func (f *fakeTC) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if strings.Contains(r.URL.String()+fmt.Sprint(r.Header)+string(body), tcTestKey) {
		f.leak = true
	}
	answer := func(v map[string]any) {
		v["RequestId"] = "req"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"Response": v})
	}
	fail := func(code string) {
		answer(map[string]any{"Error": map[string]any{"Code": code, "Message": "simulated " + code}})
	}
	action := r.Header.Get("X-TC-Action")
	f.calls = append(f.calls, action)
	var p map[string]any
	json.Unmarshal(body, &p)
	f.bodies = append(f.bodies, p)
	ts, _ := strconv.ParseInt(r.Header.Get("X-TC-Timestamp"), 10, 64)
	auth := r.Header.Get("Authorization")
	switch {
	case r.Method != "POST" || r.URL.Path != "/" || r.Header.Get("Content-Type") != "application/json; charset=utf-8" || r.Header.Get("X-TC-Version") != "2021-03-23":
		fail("InvalidParameter")
		return
	case ts != ddnsNow().Unix():
		fail("AuthFailure.SignatureExpire")
		return
	case !strings.HasPrefix(auth, "TC3-HMAC-SHA256 Credential="+tcTestID+"/"):
		fail("AuthFailure.SecretIdNotFound")
		return
	case auth != tc3Auth(tcTestID, tcTestKey, "dnspod", r.Host, action, ts, body):
		fail("AuthFailure.SignatureFailure")
		return
	case f.code != "":
		fail(f.code)
		return
	}
	same := func(a, b any) bool { return fmt.Sprint(a) == fmt.Sprint(b) }
	switch action {
	case "DescribeRecordList":
		out := []any{}
		for _, x := range f.recs {
			if x["Domain"] == p["Domain"] && x["Name"] == p["SubDomain"] && x["Type"] == p["RecordType"] {
				out = append(out, x)
			}
		}
		if len(out) == 0 { // as if ErrorOnEmpty were ignored: the client copes with both
			fail("ResourceNotFound.NoDataOfRecord")
			return
		}
		answer(map[string]any{"RecordCountInfo": map[string]any{"TotalCount": len(out)}, "RecordList": out})
	case "CreateRecord":
		f.seq++
		x := map[string]any{"RecordId": 500 + f.seq, "Domain": p["Domain"], "Name": p["SubDomain"], "Type": p["RecordType"], "Value": p["Value"],
			"Line": p["RecordLine"], "LineId": p["RecordLineId"], "TTL": 600, "Status": "ENABLE", "Weight": nil}
		if p["TTL"] != nil {
			x["TTL"] = p["TTL"]
		}
		f.recs = append(f.recs, x)
		answer(map[string]any{"RecordId": x["RecordId"]})
	case "ModifyRecord":
		for _, x := range f.recs {
			if same(x["RecordId"], p["RecordId"]) && x["Domain"] == p["Domain"] {
				x["Name"], x["Type"], x["Value"], x["Line"] = p["SubDomain"], p["RecordType"], p["Value"], p["RecordLine"]
				x["TTL"], x["Status"], x["Weight"] = 600, "ENABLE", nil // left out = the defaults
				for _, k := range []string{"TTL", "Status", "Weight"} {
					if p[k] != nil {
						x[k] = p[k]
					}
				}
				if p["RecordLineId"] != nil {
					x["LineId"] = p["RecordLineId"]
				}
				answer(map[string]any{"RecordId": x["RecordId"]})
				return
			}
		}
		fail("InvalidParameter.RecordIdInvalid")
	case "DescribeDomainList":
		l := []any{}
		for _, d := range f.domains {
			l = append(l, map[string]any{"DomainId": 1, "Name": d, "Status": "ENABLE"})
		}
		answer(map[string]any{"DomainCountInfo": map[string]any{"AllTotal": len(l)}, "DomainList": l})
	case "DeleteRecord":
		for i, x := range f.recs {
			if same(x["RecordId"], p["RecordId"]) && x["Domain"] == p["Domain"] {
				f.recs = append(f.recs[:i], f.recs[i+1:]...)
				answer(map[string]any{})
				return
			}
		}
		fail("InvalidParameter.RecordIdInvalid")
	default:
		fail("InvalidAction")
	}
}

func (f *fakeTC) take() ([]string, []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, b := f.calls, f.bodies
	f.calls, f.bodies = nil, nil
	return c, b
}

// signedEnv: ddnsEnv plus a fake AliDNS and DNSPod and their secrets.
func signedEnv(t *testing.T) (*Config, *fakeAli, *fakeTC, *time.Time, map[string][]net.IP) {
	c, _, now, addrs := ddnsEnv(t)
	fa, ft := &fakeAli{}, &fakeTC{}
	sa, st := httptest.NewServer(http.HandlerFunc(fa.handler)), httptest.NewServer(http.HandlerFunc(ft.handler))
	t.Cleanup(sa.Close)
	t.Cleanup(st.Close)
	a, b := aliAPIBase, tcAPIBase
	aliAPIBase, tcAPIBase = sa.URL, st.URL
	t.Cleanup(func() { aliAPIBase, tcAPIBase = a, b })
	c.secrets["ali_key"], c.secrets["tc_key"] = aliTestSecret, tcTestKey
	return c, fa, ft, now, addrs
}

// setRecords replaces the DDNS records, applies the defaults and validates.
func setRecords(t *testing.T, c *Config, rs ...DDNSRecord) {
	t.Helper()
	c.Services.DDNS.Records = rs
	c.defaults()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
}

// noSecret fails when any of the places a secret must never reach holds one.
func ddnsNoSecret(t *testing.T, c *Config, rows []ddnsState, secrets ...string) {
	t.Helper()
	b, _ := os.ReadFile(ddnsStateFile)
	st, _ := json.Marshal(ddnsStatus(c))
	sum, _ := json.Marshal(ddnsSummary(c))
	rw, _ := json.Marshal(rows)
	ev, _ := json.Marshal(eventRecent(eventKeep))
	for what, data := range map[string]string{"state": string(b), "status": string(st), "summary": string(sum), "rows": string(rw), "events": string(ev)} {
		for _, s := range secrets {
			for _, v := range []string{s, url.QueryEscape(s), s[:len(s)/2+1]} {
				if strings.Contains(data, v) {
					t.Errorf("%s contains a secret (%q): %s", what, v, data)
				}
			}
		}
	}
}

func TestDDNSAliDNS(t *testing.T) {
	c, f, _, now, addrs := signedEnv(t)
	addrs["br-lan"] = []net.IP{net.ParseIP("2001:db8:1:2::1")}
	setRecords(t, c, DDNSRecord{Name: "home.example.com", Provider: "alidns", Zone: "example.com", KeyID: aliTestID, Key: "ali_key", IPv6: "router"})
	// two A records (default line, a carrier line with its own TTL), no AAAA; another name is left alone
	f.recs = []map[string]any{
		{"RecordId": "101", "DomainName": "example.com", "RR": "home", "Type": "A", "Value": "203.0.113.99", "TTL": 600, "Line": "default", "Locked": false},
		{"RecordId": "102", "DomainName": "example.com", "RR": "home", "Type": "A", "Value": "203.0.113.98", "TTL": 1200, "Line": "telecom", "Locked": false},
		{"RecordId": "103", "DomainName": "example.com", "RR": "nas", "Type": "A", "Value": "203.0.113.97", "TTL": 600, "Line": "default", "Locked": false},
	}
	rows, err := ddnsSync(c, ddnsRun{})
	if err != nil {
		t.Fatal(err)
	}
	calls, ps := f.take()
	if strings.Join(calls, " ") != "DescribeSubDomainRecords UpdateDomainRecord UpdateDomainRecord DescribeSubDomainRecords AddDomainRecord" {
		t.Fatalf("calls: %v", calls)
	}
	if p := ps[0]; p["SubDomain"] != "home.example.com" || p["DomainName"] != "example.com" || p["Type"] != "A" {
		t.Errorf("describe: %v", p)
	}
	// only the value changes: the line and the TTL of each record are sent back as they were
	if p := ps[1]; p["RecordId"] != "101" || p["Value"] != "192.0.2.10" || p["TTL"] != "600" || p["Line"] != "default" || p["RR"] != "home" {
		t.Errorf("update 101: %v", p)
	}
	if p := ps[2]; p["RecordId"] != "102" || p["TTL"] != "1200" || p["Line"] != "telecom" {
		t.Errorf("update 102: %v", p)
	}
	if p := ps[4]; p["RR"] != "home" || p["Type"] != "AAAA" || p["Value"] != "2001:db8:1:2::1" || p["TTL"] != "" || p["DomainName"] != "example.com" {
		t.Errorf("add: %v", p)
	}
	if f.recs[2]["Value"] != "203.0.113.97" || f.recs[1]["TTL"] != 1200 {
		t.Errorf("records: %v", f.recs)
	}
	if len(rows) != 2 || rows[0].Published != "192.0.2.10" || rows[1].Published != "2001:db8:1:2::1" || rows[0].Provider != "alidns" {
		t.Fatalf("rows: %+v", rows)
	}
	// unchanged: nothing is asked
	*now = now.Add(10 * time.Minute)
	ddnsSync(c, ddnsRun{daily: true})
	if calls, _ := f.take(); len(calls) != 0 {
		t.Errorf("unchanged address: %v", calls)
	}
	// a configured TTL is set also where only the TTL differs; the apex is RR "@"
	setRecords(t, c, DDNSRecord{Name: "example.com", Provider: "alidns", Zone: "example.com", KeyID: aliTestID, Key: "ali_key", TTL: 300})
	f.recs = append(f.recs, map[string]any{"RecordId": "104", "DomainName": "example.com", "RR": "@", "Type": "A", "Value": "192.0.2.10", "TTL": 600, "Line": "default", "Locked": false})
	ddnsSync(c, ddnsRun{})
	if calls, ps := f.take(); len(calls) != 2 || ps[1]["RecordId"] != "104" || ps[1]["TTL"] != "300" || ps[1]["RR"] != "@" {
		t.Errorf("apex / TTL: %v %v", calls, ps)
	}
	// a locked record is reported, not forced
	f.recs[len(f.recs)-1]["Locked"], f.recs[len(f.recs)-1]["Value"] = true, "203.0.113.1"
	rows, _ = ddnsSync(c, ddnsRun{retry: true, check: true})
	if !strings.Contains(rows[0].Error, "locked") {
		t.Errorf("locked: %+v", rows[0])
	}
	f.take()
	// a server error backs off; a wrong secret stops the record (SignatureDoesNotMatch)
	f.status, f.code = 503, "ServiceUnavailable"
	rows, _ = ddnsSync(c, ddnsRun{retry: true, check: true})
	if rows[0].Stopped || !strings.Contains(rows[0].Error, "AliDNS: HTTP 503 (ServiceUnavailable: simulated ServiceUnavailable)") {
		t.Errorf("503: %+v", rows[0])
	}
	f.status = 0
	c.secrets["ali_key"] = "ali-wrong-secret-0123456789abc"
	rows, _ = ddnsSync(c, ddnsRun{retry: true})
	if !rows[0].Stopped || !strings.Contains(rows[0].Error, "AliDNS refused the key: HTTP 400 (SignatureDoesNotMatch") {
		t.Errorf("wrong secret: %+v", rows[0])
	}
	c.Services.DDNS.Records[0].KeyID = "LTAI0000otherkey0000"
	rows, _ = ddnsSync(c, ddnsRun{retry: true})
	if !rows[0].Stopped || !strings.Contains(rows[0].Error, "InvalidAccessKeyId.NotFound") {
		t.Errorf("unknown key id: %+v", rows[0])
	}
	if f.leak {
		t.Error("the AccessKey secret was sent")
	}
	ddnsNoSecret(t, c, rows, aliTestSecret, "ali-wrong-secret-0123456789abc")
}

func TestDDNSDNSPod(t *testing.T) {
	c, _, f, now, addrs := signedEnv(t)
	addrs["br-lan"] = []net.IP{net.ParseIP("2001:db8:1:2::1")}
	setRecords(t, c, DDNSRecord{Name: "home.example.com", Provider: "dnspod", Zone: "example.com", KeyID: tcTestID, Key: "tc_key", IPv6: "router"})
	w := 10
	f.recs = []map[string]any{
		{"RecordId": 11, "Domain": "example.com", "Name": "home", "Type": "A", "Value": "203.0.113.99", "Line": "默认", "LineId": "0", "TTL": 600, "Status": "ENABLE", "Weight": nil},
		{"RecordId": 12, "Domain": "example.com", "Name": "home", "Type": "A", "Value": "203.0.113.98", "Line": "电信", "LineId": "10=0", "TTL": 1200, "Status": "DISABLE", "Weight": w},
		{"RecordId": 13, "Domain": "example.com", "Name": "www", "Type": "A", "Value": "203.0.113.97", "Line": "默认", "LineId": "0", "TTL": 600, "Status": "ENABLE", "Weight": nil},
	}
	rows, err := ddnsSync(c, ddnsRun{})
	if err != nil {
		t.Fatal(err)
	}
	calls, bs := f.take()
	if strings.Join(calls, " ") != "DescribeRecordList ModifyRecord ModifyRecord DescribeRecordList CreateRecord" {
		t.Fatalf("calls: %v", calls)
	}
	if b := bs[0]; b["Domain"] != "example.com" || b["SubDomain"] != "home" || b["RecordType"] != "A" || b["ErrorOnEmpty"] != "no" {
		t.Errorf("list: %v", b)
	}
	// line, TTL, status and weight are kept; only the value changes
	if b := bs[2]; fmt.Sprint(b["RecordId"]) != "12" || b["RecordLine"] != "电信" || b["RecordLineId"] != "10=0" || fmt.Sprint(b["TTL"]) != "1200" ||
		b["Status"] != "DISABLE" || fmt.Sprint(b["Weight"]) != "10" || b["Value"] != "192.0.2.10" || b["SubDomain"] != "home" {
		t.Errorf("modify 12: %v", b)
	}
	if b := bs[4]; b["RecordType"] != "AAAA" || b["RecordLine"] != "默认" || b["RecordLineId"] != "0" || b["Value"] != "2001:db8:1:2::1" || b["TTL"] != nil {
		t.Errorf("create: %v", b)
	}
	if f.recs[2]["Value"] != "203.0.113.97" || f.recs[1]["Status"] != "DISABLE" || fmt.Sprint(f.recs[1]["TTL"]) != "1200" {
		t.Errorf("records: %v", f.recs)
	}
	if rows[0].Published != "192.0.2.10" || rows[1].Published != "2001:db8:1:2::1" {
		t.Fatalf("rows: %+v", rows)
	}
	*now = now.Add(time.Hour)
	ddnsSync(c, ddnsRun{})
	if calls, _ := f.take(); len(calls) != 0 {
		t.Errorf("unchanged address: %v", calls)
	}
	// wildcard: SubDomain "*"
	setRecords(t, c, DDNSRecord{Name: "*.example.com", Provider: "dnspod", Zone: "example.com", KeyID: tcTestID, Key: "tc_key"})
	ddnsSync(c, ddnsRun{})
	if _, bs := f.take(); len(bs) != 2 || bs[1]["SubDomain"] != "*" {
		t.Errorf("wildcard: %v", bs)
	}
	// a clock that is off is retried; refused keys stop the record
	f.code = "AuthFailure.SignatureExpire"
	rows, _ = ddnsSync(c, ddnsRun{retry: true, check: true})
	if rows[0].Stopped || !strings.Contains(rows[0].Error, "SignatureExpire") {
		t.Errorf("expired signature: %+v", rows[0])
	}
	f.code = ""
	c.secrets["tc_key"] = "tc-wrong-secret-key-0123456789ab"
	rows, _ = ddnsSync(c, ddnsRun{retry: true})
	if !rows[0].Stopped || !strings.Contains(rows[0].Error, "DNSPod refused the key: HTTP 200 (AuthFailure.SignatureFailure") {
		t.Errorf("wrong key: %+v", rows[0])
	}
	if f.leak {
		t.Error("the SecretKey was sent")
	}
	ddnsNoSecret(t, c, rows, tcTestKey, "tc-wrong-secret-key-0123456789ab")
}

// ACME DNS-01 through AliDNS and DNSPod: a TXT record appears and is removed again.
func TestDDNSDNS01Signed(t *testing.T) {
	c, fa, ft, _, _ := signedEnv(t)
	ctx := context.Background()
	pa := &aliDNS01{hc: ddnsHTTP(), keyID: aliTestID, secret: aliTestSecret}
	del, err := pa.present(ctx, "_acme-challenge.nas.example.com", "tXt-VaLuE_0123")
	if err != nil {
		t.Fatal(err)
	}
	if len(fa.recs) != 1 || fa.recs[0]["RR"] != "_acme-challenge.nas" || fa.recs[0]["DomainName"] != "example.com" || fa.recs[0]["Type"] != "TXT" ||
		fa.recs[0]["Value"] != "tXt-VaLuE_0123" || fa.recs[0]["TTL"] != 600 {
		t.Errorf("AliDNS TXT: %v", fa.recs)
	}
	del(ctx)
	if calls, _ := fa.take(); len(fa.recs) != 0 || strings.Join(calls, " ") != "GetMainDomainName AddDomainRecord DeleteDomainRecord" {
		t.Errorf("AliDNS cleanup: %v %v", calls, fa.recs)
	}
	// DNSPod: the longest domain of the account wins (a delegated sub-zone)
	ft.domains = []string{"example.com", "sub.example.com", "example.net"}
	pt := &tcDNS01{hc: ddnsHTTP(), id: tcTestID, key: tcTestKey}
	del, err = pt.present(ctx, "_acme-challenge.a.sub.example.com", "v1")
	if err != nil {
		t.Fatal(err)
	}
	del2, err := pt.present(ctx, "_acme-challenge.example.com", "v2")
	if err != nil {
		t.Fatal(err)
	}
	if len(ft.recs) != 2 || ft.recs[0]["Domain"] != "sub.example.com" || ft.recs[0]["Name"] != "_acme-challenge.a" || ft.recs[1]["Domain"] != "example.com" ||
		ft.recs[1]["Name"] != "_acme-challenge" || ft.recs[0]["Type"] != "TXT" || ft.recs[0]["Line"] != "默认" {
		t.Errorf("DNSPod TXT: %v", ft.recs)
	}
	if _, err := pt.present(ctx, "_acme-challenge.example.org", "v3"); err == nil || !strings.Contains(err.Error(), "no domain of the account") {
		t.Errorf("unknown domain: %v", err)
	}
	del(ctx)
	del2(ctx)
	if calls, _ := ft.take(); len(ft.recs) != 0 || strings.Count(strings.Join(calls, " "), "DescribeDomainList") != 1 {
		t.Errorf("DNSPod cleanup: %v %v", calls, ft.recs)
	}
	// wrong credentials: a refusal without the secret in it
	bad := &tcDNS01{hc: ddnsHTTP(), id: tcTestID, key: "tc-wrong-secret-key-0123456789ab"}
	if _, err := bad.present(ctx, "_acme-challenge.example.com", "x"); err == nil || !strings.Contains(err.Error(), "refused the key") || strings.Contains(err.Error(), "wrong-secret") {
		t.Errorf("DNSPod refused: %v", err)
	}
	// services.edge.acme picks the provider
	c.Services.Edge.ACME = EdgeACME{Provider: "alidns", KeyID: aliTestID, Key: "ali_key"}
	if p, err := edgeDNS01For(c); err != nil || p.(*aliDNS01).secret != aliTestSecret {
		t.Errorf("edge alidns: %T %v", p, err)
	}
	c.Services.Edge.ACME = EdgeACME{Provider: "dnspod", KeyID: tcTestID, Key: "tc_key"}
	if p, err := edgeDNS01For(c); err != nil || p.(*tcDNS01).key != tcTestKey {
		t.Errorf("edge dnspod: %T %v", p, err)
	}
	if fa.leak || ft.leak {
		t.Error("a secret was sent")
	}
}
