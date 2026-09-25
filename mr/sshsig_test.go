package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic FIDO keys and signatures, built the way a security key and ssh-keygen -Y sign make them
// (PROTOCOL.sshsig, PROTOCOL.u2f): no hardware, no home keys.

type testSigner struct {
	typ  string
	blob []byte // public key blob
	ed   ed25519.PrivateKey
	ec   *ecdsa.PrivateKey
}

func (k *testSigner) line(comment string) string {
	return k.typ + " " + base64.StdEncoding.EncodeToString(k.blob) + " " + comment
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func newSKEd25519(t *testing.T) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{typ: skEd25519, ed: priv, blob: cat(sshString([]byte(skEd25519)), sshString(pub), sshString([]byte("ssh:")))}
}

func newSKECDSA(t *testing.T) *testSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	q := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)
	return &testSigner{typ: skECDSA, ec: priv, blob: cat(sshString([]byte(skECDSA)), sshString([]byte("nistp256")), sshString(q), sshString([]byte("ssh:")))}
}

// newPlainEd25519: an ordinary (not security-key) ed25519 key.
func newPlainEd25519(t *testing.T) *testSigner {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &testSigner{typ: "ssh-ed25519", ed: priv, blob: cat(sshString([]byte("ssh-ed25519")), sshString(pub))}
}

func mpint(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

// sign: an armored SSHSIG over msg in namespace ns, with the FIDO flags and counter given.
func (k *testSigner) sign(t *testing.T, msg []byte, ns string, flags byte, counter uint32) string {
	t.Helper()
	s := &sshSig{namespace: ns, hashAlg: "sha512"}
	signed, err := s.signedData(msg)
	if err != nil {
		t.Fatal(err)
	}
	var sig []byte
	app := sha256.Sum256([]byte("ssh:"))
	tail := binary.BigEndian.AppendUint32([]byte{flags}, counter)
	switch k.typ {
	case skEd25519:
		sig = cat(sshString([]byte(k.typ)), sshString(ed25519.Sign(k.ed, skSignedBlob(app, flags, counter, signed))), tail)
	case skECDSA:
		h := sha256.Sum256(skSignedBlob(app, flags, counter, signed))
		r, ss, err := ecdsa.Sign(rand.Reader, k.ec, h[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = cat(sshString([]byte(k.typ)), sshString(cat(sshString(mpint(r)), sshString(mpint(ss)))), tail)
	default: // a plain key: no flags, no counter
		sig = cat(sshString([]byte(k.typ)), sshString(ed25519.Sign(k.ed, signed)))
	}
	blob := cat([]byte("SSHSIG"), binary.BigEndian.AppendUint32(nil, 1), sshString(k.blob), sshString([]byte(ns)),
		sshString(nil), sshString([]byte("sha512")), sshString(sig))
	enc := base64.StdEncoding.EncodeToString(blob)
	var b strings.Builder
	b.WriteString(sigArmorBegin + "\n")
	for len(enc) > 70 {
		b.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	b.WriteString(enc + "\n" + sigArmorEnd + "\n")
	return b.String()
}

// An approval counts only from a listed FIDO key, touched, over exactly this text, in namespace mr-plan.
func TestVerifyApproval(t *testing.T) {
	owner, spare, ec := newSKEd25519(t), newSKEd25519(t), newSKECDSA(t)
	approvers := []string{owner.line("owner-key"), ec.line("old-key")}
	msg := []byte("mini-router change approval\nplan: 0123456789abcdef\n")
	if who, err := verifyApproval(owner.sign(t, msg, "mr-plan", 0x01, 7), msg, "mr-plan", approvers); err != nil || who.Comment != "owner-key" || who.Counter != 7 || !strings.HasPrefix(who.FP, "SHA256:") {
		t.Fatalf("ed25519-sk, touched: %v %+v", err, who)
	}
	if who, err := verifyApproval(ec.sign(t, msg, "mr-plan", 0x05, 1), msg, "mr-plan", approvers); err != nil || who.Comment != "old-key" {
		t.Fatalf("ecdsa-sk, touched + verified: %v %+v", err, who)
	}
	good := owner.sign(t, msg, "mr-plan", 0x01, 8)
	flip := func(sig string, at int) string { // one byte of the decoded blob changed
		body := strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(sig), sigArmorBegin), sigArmorEnd)), "")
		raw, _ := base64.StdEncoding.DecodeString(body)
		raw[len(raw)-at] ^= 0x04 // for the flags: user-verified, so user-present stays set
		return sigArmorBegin + "\n" + base64.StdEncoding.EncodeToString(raw) + "\n" + sigArmorEnd + "\n"
	}
	for name, c := range map[string]struct {
		sig, want string
		msg       []byte
	}{
		"not touched (no user-presence flag)": {owner.sign(t, msg, "mr-plan", 0x00, 9), "not touched", msg},
		"verified but not touched":            {owner.sign(t, msg, "mr-plan", 0x04, 9), "not touched", msg},
		"another namespace":                   {owner.sign(t, msg, "file", 0x01, 9), "namespace", msg},
		"a FIDO key that is no approver":      {spare.sign(t, msg, "mr-plan", 0x01, 9), "not in guard.approvers", msg},
		"an ordinary ed25519 key":             {newPlainEd25519(t).sign(t, msg, "mr-plan", 0, 0), "FIDO security key", msg},
		"another text":                        {good, "does not match", []byte("mini-router change approval\nplan: fedcba9876543210\n")},
		"counter changed after signing":       {flip(good, 1), "does not match", msg},
		"flags changed after signing":         {flip(good, 5), "does not match", msg},
		"signature bytes changed":             {flip(good, 20), "does not match", msg},
		"garbage":                             {"hello", "not an SSH signature", msg},
		"bad base64":                          {sigArmorBegin + "\n!!!!\n" + sigArmorEnd, "base64", msg},
		"truncated":                           {sigArmorBegin + "\nU1NIU0lHAAAAAQ==\n" + sigArmorEnd, "malformed", msg},
	} {
		if _, err := verifyApproval(c.sig, c.msg, "mr-plan", approvers); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", name, err, c.want)
		}
	}
	// no approvers: nothing is accepted
	if _, err := verifyApproval(good, msg, "mr-plan", nil); err == nil {
		t.Error("accepted without approvers")
	}
}

// Parity with OpenSSH: ssh-keygen -Y verify accepts the synthetic sk signatures — so they are built the
// way a security key signs — and mr parses a real ssh-keygen -Y sign file the same way (an ordinary key:
// parsed, refused as not FIDO; its signature checks out over mr's signed-data layout). ssh-keygen -Y
// verify does not insist on the user-presence flag (sshd does, for logins); mr does. Skipped without
// ssh-keygen.
func TestApprovalMatchesOpenSSH(t *testing.T) {
	kg, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("no ssh-keygen")
	}
	d := t.TempDir()
	msgF := filepath.Join(d, "plan.txt")
	msg := []byte("mini-router change approval\nsha256: 00\n")
	os.WriteFile(msgF, msg, 0600)
	verify := func(signer string, k *testSigner, sig string) error {
		os.WriteFile(filepath.Join(d, "allowed"), []byte(signer+" "+k.line("x")+"\n"), 0600)
		os.WriteFile(msgF+".sig", []byte(sig), 0600)
		cmd := exec.Command(kg, "-Y", "verify", "-f", filepath.Join(d, "allowed"), "-I", signer, "-n", "mr-plan", "-s", msgF+".sig")
		cmd.Stdin = strings.NewReader(string(msg))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("ssh-keygen: %s", out)
		}
		return err
	}
	for _, k := range []*testSigner{newSKEd25519(t), newSKECDSA(t)} {
		if err := verify("owner@example", k, k.sign(t, msg, "mr-plan", 0x01, 3)); err != nil {
			t.Errorf("%s: ssh-keygen refuses mr's test signature: %v", k.typ, err)
		}
		if err := verify("owner@example", k, k.sign(t, msg, "mr-plan", 0x05, 4)); err != nil {
			t.Errorf("%s (user verified too): ssh-keygen refuses mr's test signature: %v", k.typ, err)
		}
		if err := verify("owner@example", k, k.sign(t, msg, "file", 0x01, 6)); err == nil {
			t.Errorf("%s: ssh-keygen accepts the wrong namespace", k.typ)
		}
	}
	key := filepath.Join(d, "id_ed25519")
	if out, err := exec.Command(kg, "-q", "-t", "ed25519", "-N", "", "-C", "ci", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -t ed25519: %v %s", err, out)
	}
	os.Remove(msgF + ".sig") // ssh-keygen does not overwrite it
	if out, err := exec.Command(kg, "-Y", "sign", "-n", "mr-plan", "-f", key, msgF).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v %s", err, out)
	}
	sig, _ := os.ReadFile(msgF + ".sig")
	pub, _ := os.ReadFile(key + ".pub")
	if _, err := verifyApproval(string(sig), msg, "mr-plan", []string{strings.TrimSpace(string(pub))}); err == nil || !strings.Contains(err.Error(), "FIDO security key") {
		t.Errorf("real ordinary-key signature: %v", err)
	}
	s, err := parseSSHSig(string(sig))
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := s.signedData(msg)
	r := &sshReader{b: s.sig}
	r.str()
	raw := r.str()
	pr := &sshReader{b: s.pub}
	pr.str()
	if !ed25519.Verify(ed25519.PublicKey(pr.str()), signed, raw) {
		t.Error("mr's signed-data layout differs from OpenSSH's")
	}
}
