package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"myceliam/internal/operr"
)

func selfSignedRSACert(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().UTC().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}

func selfSignedECCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().UTC().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func b64URLDecodeUint(t *testing.T, value string) *big.Int {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return new(big.Int).SetBytes(raw)
}

func TestPemCertToJWKMatchesPublicNumbers(t *testing.T) {
	pem, key := selfSignedRSACert(t)
	jwk, err := PemCertToJWK(pem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if jwk.Kty != "RSA" || jwk.Use != "sig" || jwk.Alg != "RS256" {
		t.Fatalf("unexpected jwk: %+v", jwk)
	}
	if b64URLDecodeUint(t, jwk.N).Cmp(key.PublicKey.N) != 0 {
		t.Fatalf("n mismatch")
	}
	if b64URLDecodeUint(t, jwk.E).Int64() != int64(key.PublicKey.E) {
		t.Fatalf("e mismatch")
	}
	if len(jwk.Kid) != 16 {
		t.Fatalf("expected 16-char kid, got %q", jwk.Kid)
	}
}

func TestPemCertToJWKSStringWrapsSingleKey(t *testing.T) {
	pem, _ := selfSignedRSACert(t)
	docStr, err := PemCertToJWKSString(pem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(docStr), &doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc) != 1 {
		t.Fatalf("expected exactly one top-level key, got %v", doc)
	}
	var keys []JWK
	if err := json.Unmarshal(doc["keys"], &keys); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected exactly one key, got %d", len(keys))
	}
}

func TestRejectsMalformedPEM(t *testing.T) {
	_, err := PemCertToJWK([]byte("not a real cert"))
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestRejectsNonRSAKey(t *testing.T) {
	pem := selfSignedECCert(t)
	_, err := PemCertToJWK(pem)
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}
