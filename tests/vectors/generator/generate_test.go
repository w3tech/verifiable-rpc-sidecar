// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

// Package confidentialvectors regenerates ../confidential.json with the Go
// standard library only, independently of the Rust implementation.
//
//	go test ./...           check that ../confidential.json is reproduced byte for byte
//	go test ./... -update   rewrite ../confidential.json
package confidentialvectors

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"runtime"
	"testing"
	"testing/cryptotest"
)

const outPath = "../confidential.json"

var update = flag.Bool("update", false, "rewrite "+outPath)

type keyConversion struct {
	Name             string `json:"name"`
	Seed             string `json:"seed"`
	Ed25519PublicKey string `json:"ed25519_public_key"`
	SkR              string `json:"skR"`
	PkR              string `json:"pkR"`
}

type field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type innerRequest struct {
	Method    string  `json:"method"`
	Scheme    string  `json:"scheme"`
	Authority string  `json:"authority"`
	Path      string  `json:"path"`
	Fields    []field `json:"fields"`
	Body      string  `json:"body"`
}

type innerResponse struct {
	Status int     `json:"status"`
	Fields []field `json:"fields"`
	Body   string  `json:"body"`
}

type envelope struct {
	Name                 string        `json:"name"`
	SkR                  string        `json:"skR"`
	PkR                  string        `json:"pkR"`
	Request              innerRequest  `json:"request"`
	BhttpRequest         string        `json:"bhttp_request"`
	Hdr                  string        `json:"hdr"`
	Info                 string        `json:"info"`
	Enc                  string        `json:"enc"`
	EncapsulatedRequest  string        `json:"encapsulated_request"`
	ExportSecret         string        `json:"export_secret"`
	Response             innerResponse `json:"response"`
	BhttpResponse        string        `json:"bhttp_response"`
	ResponseNonce        string        `json:"response_nonce"`
	AeadKey              string        `json:"aead_key"`
	AeadNonce            string        `json:"aead_nonce"`
	EncapsulatedResponse string        `json:"encapsulated_response"`
	OuterStatus          int           `json:"outer_status,omitempty"`
}

type plaintextError struct {
	Name        string `json:"name"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body"`
}

type suite struct {
	KeyID  int `json:"key_id"`
	KemID  int `json:"kem_id"`
	KdfID  int `json:"kdf_id"`
	AeadID int `json:"aead_id"`
}

type provenance struct {
	Generator  string `json:"generator"`
	GoVersion  string `json:"go_version"`
	Randomness string `json:"randomness"`
}

type vectors struct {
	Description     string           `json:"description"`
	ContractVersion string           `json:"contract_version"`
	Suite           suite            `json:"suite"`
	Provenance      provenance       `json:"provenance"`
	KeyConversion   []keyConversion  `json:"key_conversion"`
	Envelopes       []envelope       `json:"envelopes"`
	PreDecapErrors  []plaintextError `json:"pre_decapsulation_errors"`
}

var testSeed = []byte{
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
	0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
}

var hdr = []byte{0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x02}

// skR = clamp(SHA-512(seed)[0:32]), RFC 8032 §5.1.5 and RFC 7748 §5.
func clampedScalar(seed []byte) []byte {
	h := sha512.Sum512(seed)
	s := append([]byte{}, h[:32]...)
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return s
}

// Birational map u = (1+y)/(1-y) mod p, RFC 7748 §4.1.
func edwardsToMontgomery(pub []byte) []byte {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	le := append([]byte{}, pub...)
	le[31] &= 0x7f
	y := new(big.Int).SetBytes(reverse(le))
	num := new(big.Int).Add(big.NewInt(1), y)
	den := new(big.Int).Sub(big.NewInt(1), y)
	den.Mod(den, p)
	den.ModInverse(den, p)
	u := new(big.Int).Mul(num, den)
	u.Mod(u, p)
	return reverse(u.FillBytes(make([]byte, 32)))
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

func appendVarint(b []byte, v int) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(0x40|v>>8), byte(v))
	default:
		panic("varint too large for these vectors")
	}
}

func appendVec(b, v []byte) []byte {
	return append(appendVarint(b, len(v)), v...)
}

func appendFields(b []byte, fields []field) []byte {
	var sec []byte
	for _, f := range fields {
		sec = appendVec(sec, []byte(f.Name))
		sec = appendVec(sec, []byte(f.Value))
	}
	return appendVec(b, sec)
}

// RFC 9292 known-length request with an empty trailer section.
func encodeRequest(r innerRequest) []byte {
	b := appendVarint(nil, 0)
	b = appendVec(b, []byte(r.Method))
	b = appendVec(b, []byte(r.Scheme))
	b = appendVec(b, []byte(r.Authority))
	b = appendVec(b, []byte(r.Path))
	b = appendFields(b, r.Fields)
	b = appendVec(b, []byte(r.Body))
	return appendFields(b, nil)
}

// RFC 9292 known-length response with an empty trailer section.
func encodeResponse(r innerResponse) []byte {
	b := appendVarint(nil, 1)
	b = appendVarint(b, r.Status)
	b = appendFields(b, r.Fields)
	b = appendVec(b, []byte(r.Body))
	return appendFields(b, nil)
}

func generate(t *testing.T) []byte {
	cryptotest.SetGlobalRandom(t, 1)

	edPub := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	skR := clampedScalar(testSeed)
	xPriv, err := ecdh.X25519().NewPrivateKey(skR)
	if err != nil {
		t.Fatal(err)
	}
	pkR := xPriv.PublicKey().Bytes()
	if !bytes.Equal(pkR, edwardsToMontgomery(edPub)) {
		t.Fatal("X25519 public key of skR differs from the Montgomery form of the Ed25519 public key")
	}

	req := innerRequest{
		Method: "POST", Scheme: "https", Authority: "localhost", Path: "/",
		Fields: []field{{"content-type", "application/json"}},
		Body:   `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`,
	}
	res := innerResponse{
		Status: 200,
		Fields: []field{{"content-type", "application/json"}},
		Body:   `{"jsonrpc":"2.0","id":1,"result":"0x10"}`,
	}
	ok := sealEnvelope(t, xPriv, "post-json-rpc", req, res)
	badReq := innerRequest{
		Method: "POST", Scheme: "https", Authority: "localhost", Path: "@evil.example/x",
		Fields: []field{{"content-type", "application/json"}},
		Body:   `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`,
	}
	badRes := innerResponse{
		Status: 400,
		Fields: []field{{"content-type", "application/problem+json"}},
		Body:   `{"type":"urn:vrpc:error:bad-request","title":"Bad request"}`,
	}
	bad := sealEnvelope(t, xPriv, "inner-error-bad-request", badReq, badRes)
	bad.OuterStatus = 400

	h := hex.EncodeToString
	v := vectors{
		Description: "Known-answer vectors for Ankr Confidential RPC (POST /confidential): " +
			"key conversion, encapsulated requests and responses including one encrypted inner error, " +
			"and the plaintext errors returned before decapsulation. " +
			"Byte strings are lowercase hex without a 0x prefix.",
		ContractVersion: "0.4",
		Suite:           suite{KeyID: 0, KemID: 0x0020, KdfID: 0x0001, AeadID: 0x0002},
		Provenance: provenance{
			Generator:  "tests/vectors/generator: Go standard library (crypto/ed25519, crypto/ecdh, crypto/hpke, crypto/hkdf, crypto/aes, crypto/cipher)",
			GoVersion:  runtime.Version(),
			Randomness: "testing/cryptotest.SetGlobalRandom, seed 1",
		},
		KeyConversion: []keyConversion{{
			Name: "test-seed", Seed: h(testSeed), Ed25519PublicKey: h(edPub), SkR: h(skR), PkR: h(pkR),
		}},
		Envelopes: []envelope{ok, bad},
		PreDecapErrors: []plaintextError{
			{
				Name: "ohttp-key", Status: 400, ContentType: "application/problem+json",
				Body: h([]byte(`{"type":"https://iana.org/assignments/http-problem-types#ohttp-key","title":"Oblivious HTTP key configuration not acceptable"}`)),
			},
			{Name: "request-too-large", Status: 413, Body: ""},
			{Name: "method-not-allowed", Status: 405, Body: ""},
		},
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func sealEnvelope(t *testing.T, xPriv *ecdh.PrivateKey, name string, req innerRequest, res innerResponse) envelope {
	skR := xPriv.Bytes()
	pkR := xPriv.PublicKey().Bytes()
	bhttpReq := encodeRequest(req)
	bhttpRes := encodeResponse(res)

	info := append([]byte("message/bhttp request\x00"), hdr...)
	pk, err := hpke.NewDHKEMPublicKey(xPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sender.Seal(nil, bhttpReq)
	if err != nil {
		t.Fatal(err)
	}
	encapsulatedReq := append(append(append([]byte{}, hdr...), enc...), ct...)
	secret, err := sender.Export("message/bhttp response", 32)
	if err != nil {
		t.Fatal(err)
	}

	sk, err := hpke.NewDHKEMPrivateKey(xPriv)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := hpke.NewRecipient(enc, sk, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := recipient.Open(nil, ct); err != nil || !bytes.Equal(pt, bhttpReq) {
		t.Fatal("recipient could not open the request", err)
	}

	responseNonce := make([]byte, 32)
	if _, err := rand.Read(responseNonce); err != nil {
		t.Fatal(err)
	}
	salt := append(append([]byte{}, enc...), responseNonce...)
	prk, err := hkdf.Extract(sha256.New, secret, salt)
	if err != nil {
		t.Fatal(err)
	}
	aeadKey, err := hkdf.Expand(sha256.New, prk, "key", 32)
	if err != nil {
		t.Fatal(err)
	}
	aeadNonce, err := hkdf.Expand(sha256.New, prk, "nonce", 12)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	encapsulatedRes := append(append([]byte{}, responseNonce...), gcm.Seal(nil, aeadNonce, bhttpRes, nil)...)

	h := hex.EncodeToString
	return envelope{
		Name: name, SkR: h(skR), PkR: h(pkR),
		Request: req, BhttpRequest: h(bhttpReq),
		Hdr: h(hdr), Info: h(info), Enc: h(enc),
		EncapsulatedRequest: h(encapsulatedReq), ExportSecret: h(secret),
		Response: res, BhttpResponse: h(bhttpRes), ResponseNonce: h(responseNonce),
		AeadKey: h(aeadKey), AeadNonce: h(aeadNonce), EncapsulatedResponse: h(encapsulatedRes),
	}
}

func TestConfidentialVectors(t *testing.T) {
	got := generate(t)
	if *update {
		if err := os.WriteFile(outPath, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is not reproduced by this generator; rerun with -update and review the diff", outPath)
	}
}
