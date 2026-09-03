// Package jwks ports pythonoperator/src/myceliam/jwks.py: converting a
// signedjwt client's PEM certificate into the JWKS document Keycloak's
// jwks.string client attribute expects.
package jwks

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	"myceliam/internal/operr"
)

// JWK is a single JSON Web Key, RSA-only (the only key type signedjwt clients
// support, per pem_cert_to_jwk's isinstance check in the Python original).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Document is a JWKS document, suitable for Keycloak's jwks.string attribute.
type Document struct {
	Keys []JWK `json:"keys"`
}

func b64URLUint(v *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(v.Bytes())
}

// PemCertToJWK extracts the RSA public key from a PEM-encoded X.509
// certificate and builds a JWK.
//
// Returns an *operr.Permanent if the PEM can't be parsed, or the certificate's
// public key isn't RSA.
func PemCertToJWK(pemBytes []byte) (*JWK, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, operr.Permanentf("Could not parse PEM certificate: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, operr.Permanentf("Could not parse PEM certificate: %v", err)
	}

	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, operr.Permanentf(
			"Only RSA public keys are supported for signedjwt clients, got %T", cert.PublicKey,
		)
	}

	sum := sha256.Sum256(cert.Raw) // cert.Raw is the DER encoding, same as public_bytes(Encoding.DER)
	kid := hex.EncodeToString(sum[:])[:16]

	return &JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   b64URLUint(pub.N),
		E:   b64URLUint(big.NewInt(int64(pub.E))),
	}, nil
}

// PemCertToJWKSString builds a JWKS document (as a JSON string, suitable for
// Keycloak's jwks.string attribute).
func PemCertToJWKSString(pemBytes []byte) (string, error) {
	jwk, err := PemCertToJWK(pemBytes)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(Document{Keys: []JWK{*jwk}})
	if err != nil {
		return "", fmt.Errorf("marshaling JWKS document: %w", err)
	}
	return string(b), nil
}
