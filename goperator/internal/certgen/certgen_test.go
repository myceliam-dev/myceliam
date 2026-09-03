package certgen

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestGenerateSelfSignedKeypairProducesMatchingCertAndKey(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedKeypair("my-app", 2048, 365)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse key: %v", err)
	}
	privateKey := parsedKey.(*rsa.PrivateKey)

	certPub := cert.PublicKey.(*rsa.PublicKey)
	if certPub.N.Cmp(privateKey.PublicKey.N) != 0 || certPub.E != privateKey.PublicKey.E {
		t.Fatalf("cert public key does not match private key")
	}
	if privateKey.Size()*8 != 2048 {
		t.Fatalf("expected 2048-bit key, got %d bits", privateKey.Size()*8)
	}
	if cert.Subject.CommonName != "my-app" {
		t.Fatalf("expected CN=my-app, got %v", cert.Subject.CommonName)
	}
}

func TestGenerateSelfSignedKeypairRespectsValidityWindow(t *testing.T) {
	certPEM, _, err := GenerateSelfSignedKeypair("my-app", 2048, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	delta := cert.NotAfter.Sub(cert.NotBefore)
	if delta <= 29*24*time.Hour || delta >= 31*24*time.Hour {
		t.Fatalf("expected validity window ~30 days, got %v", delta)
	}
}
