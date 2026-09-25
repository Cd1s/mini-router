package main

// SSH signatures (OpenSSH SSHSIG: `ssh-keygen -Y sign`) made with a FIDO security key — the owner's
// physical approval of a high-risk change an agent prepared (Cd1s/mini-router#37). Only security-key
// types count (sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com), and only with the
// user-presence flag set: the key was touched for this very signature. Formats: PROTOCOL.sshsig and
// PROTOCOL.u2f in OpenSSH. Standard library only (crypto/ed25519 and crypto/ecdsa are in the binary
// already, through net/http's TLS).
//
//	armored  -----BEGIN SSH SIGNATURE----- base64(blob) -----END SSH SIGNATURE-----
//	blob     "SSHSIG" u32(1) string(public key) string(namespace) string(reserved) string(hash) string(signature)
//	signed   "SSHSIG" string(namespace) string(reserved) string(hash) string(H(message))
//	sk sig   string(type) string(raw signature) byte(flags) u32(counter)
//	         the key signs sha256(application) ‖ flags ‖ counter ‖ sha256(signed)
//	         (ed25519: those bytes; ECDSA P-256: their SHA-256)

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	skEd25519     = "sk-ssh-ed25519@openssh.com"
	skECDSA       = "sk-ecdsa-sha2-nistp256@openssh.com"
	sigArmorBegin = "-----BEGIN SSH SIGNATURE-----"
	sigArmorEnd   = "-----END SSH SIGNATURE-----"
	skUserPresent = 0x01 // FIDO flag: the key was touched
)

// sshReader reads SSH wire encoding; the first error sticks.
type sshReader struct {
	b   []byte
	err error
}

func (r *sshReader) fail() {
	if r.err == nil {
		r.err = errors.New("truncated or malformed")
	}
}

func (r *sshReader) u32() uint32 {
	if r.err != nil || len(r.b) < 4 {
		r.fail()
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *sshReader) byte1() byte {
	if r.err != nil || len(r.b) < 1 {
		r.fail()
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *sshReader) str() []byte {
	n := r.u32()
	if r.err != nil || uint64(n) > uint64(len(r.b)) {
		r.fail()
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

// end: the whole input was read, without error.
func (r *sshReader) end() error {
	if r.err == nil && len(r.b) > 0 {
		r.err = errors.New("trailing data")
	}
	return r.err
}

func sshString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

type sshSig struct {
	pub       []byte // the signer's public key blob
	namespace string
	reserved  []byte
	hashAlg   string
	sig       []byte
}

// parseSSHSig reads an armored SSHSIG (the .sig file ssh-keygen -Y sign writes).
func parseSSHSig(armored string) (*sshSig, error) {
	if len(armored) > 16<<10 {
		return nil, errors.New("signature too long")
	}
	a := strings.Index(armored, sigArmorBegin)
	e := strings.Index(armored, sigArmorEnd)
	if a < 0 || e < a {
		return nil, errors.New("not an SSH signature (want the " + sigArmorBegin + " block that ssh-keygen -Y sign writes)")
	}
	body := strings.Join(strings.Fields(armored[a+len(sigArmorBegin):e]), "")
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, errors.New("SSH signature: bad base64")
	}
	if !bytes.HasPrefix(raw, []byte("SSHSIG")) {
		return nil, errors.New("SSH signature: no SSHSIG magic")
	}
	r := &sshReader{b: raw[6:]}
	if v := r.u32(); r.err == nil && v != 1 {
		return nil, fmt.Errorf("SSH signature: version %d", v)
	}
	s := &sshSig{pub: r.str(), namespace: string(r.str()), reserved: r.str(), hashAlg: string(r.str()), sig: r.str()}
	if err := r.end(); err != nil {
		return nil, fmt.Errorf("SSH signature: %v", err)
	}
	return s, nil
}

// signedData: what an SSHSIG signature covers for message msg.
func (s *sshSig) signedData(msg []byte) ([]byte, error) {
	var h []byte
	switch s.hashAlg {
	case "sha512":
		x := sha512.Sum512(msg)
		h = x[:]
	case "sha256":
		x := sha256.Sum256(msg)
		h = x[:]
	default:
		return nil, fmt.Errorf("SSH signature: unsupported hash %q", clip(s.hashAlg, 20))
	}
	out := []byte("SSHSIG")
	for _, f := range [][]byte{[]byte(s.namespace), s.reserved, []byte(s.hashAlg), h} {
		out = append(out, sshString(f)...)
	}
	return out, nil
}

func keyType(blob []byte) string {
	r := &sshReader{b: blob}
	return string(r.str())
}

func keyFP(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// approval: who approved, as recorded in the history.
type approval struct {
	FP      string `json:"fingerprint"`
	Comment string `json:"comment"`
	Type    string `json:"type"`
	Counter uint32 `json:"counter"`
}

// verifyApproval checks that armored is an SSHSIG over msg in namespace ns, made by one of keys
// (public key lines, security-key types only) with the user-presence flag set.
func verifyApproval(armored string, msg []byte, ns string, keys []string) (*approval, error) {
	s, err := parseSSHSig(armored)
	if err != nil {
		return nil, err
	}
	if s.namespace != ns {
		return nil, fmt.Errorf("signature namespace %q, want %q (ssh-keygen -Y sign -n %s)", clip(s.namespace, 40), ns, ns)
	}
	typ := keyType(s.pub)
	if typ != skEd25519 && typ != skECDSA {
		return nil, fmt.Errorf("signed with a %s key: an approval needs a FIDO security key (%s), whose touch the signature proves", clip(typ, 40), skEd25519)
	}
	var who *approval
	for _, l := range keys {
		k, err := parseAuthKey(l)
		if err != nil {
			continue
		}
		f := strings.Fields(k.line)
		if blob, err := base64.StdEncoding.DecodeString(f[1]); err == nil && bytes.Equal(blob, s.pub) {
			who = &approval{FP: k.FP, Comment: k.Comment, Type: k.Type}
			break
		}
	}
	if who == nil {
		return nil, fmt.Errorf("the signing key %s is not in guard.approvers", keyFP(s.pub))
	}
	signed, err := s.signedData(msg)
	if err != nil {
		return nil, err
	}
	sr := &sshReader{b: s.sig}
	sigType, raw, flags, counter := string(sr.str()), sr.str(), sr.byte1(), sr.u32()
	if err := sr.end(); err != nil || sigType != typ {
		return nil, fmt.Errorf("SSH signature: bad %s signature", typ)
	}
	if flags&skUserPresent == 0 {
		return nil, errors.New("the security key was not touched for this signature (user-presence flag missing)")
	}
	pr := &sshReader{b: s.pub}
	pr.str() // type
	var ok bool
	switch typ {
	case skEd25519:
		pk, application := pr.str(), pr.str()
		if pr.end() != nil || len(pk) != ed25519.PublicKeySize || len(raw) != ed25519.SignatureSize {
			return nil, errors.New("SSH signature: malformed ed25519-sk key or signature")
		}
		app := sha256.Sum256(application)
		ok = ed25519.Verify(ed25519.PublicKey(pk), skSignedBlob(app, flags, counter, signed), raw)
	case skECDSA:
		curve, q, application := pr.str(), pr.str(), pr.str()
		if pr.end() != nil || string(curve) != "nistp256" {
			return nil, errors.New("SSH signature: malformed ecdsa-sk key")
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), q)
		er := &sshReader{b: raw}
		rb, sb := er.str(), er.str()
		if x == nil || er.end() != nil || !positiveMPInt(rb) || !positiveMPInt(sb) {
			return nil, errors.New("SSH signature: malformed ecdsa-sk key or signature")
		}
		app := sha256.Sum256(application)
		h := sha256.Sum256(skSignedBlob(app, flags, counter, signed))
		ok = ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h[:], new(big.Int).SetBytes(rb), new(big.Int).SetBytes(sb))
	}
	if !ok {
		return nil, errors.New("the signature does not match this plan (signed a different text, or it was changed)")
	}
	who.Counter = counter
	return who, nil
}

// skSignedBlob: what a FIDO key signs (PROTOCOL.u2f).
func skSignedBlob(app [32]byte, flags byte, counter uint32, signed []byte) []byte {
	msg := sha256.Sum256(signed)
	out := append(app[:], flags)
	out = binary.BigEndian.AppendUint32(out, counter)
	return append(out, msg[:]...)
}

func positiveMPInt(b []byte) bool { return len(b) > 0 && len(b) <= 33 && b[0]&0x80 == 0 }
