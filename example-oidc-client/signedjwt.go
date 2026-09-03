package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// getKeycloakTokenSignedJWT authenticates via RFC 7523 private_key_jwt
// instead of a client secret — mirrors goperator's
// internal/oidc/keycloak/signedjwt.go. Unlike the operator's own
// single-certificate bootstrap credential, this DOES need a kid: this
// client's Keycloak credentials are a JWKS array (pushed by the operator via
// EnsureSignedjwtClient when it provisioned this ServiceAccount, keyed by
// kid), not a single admin-uploaded certificate — so the assertion's kid
// must match what Keycloak has on file for this client, which is exactly
// what certKid derives below.
func getKeycloakTokenSignedJWT(issuer, clientID, certPath, keyPath, scope string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("reading cert %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("reading key %s: %w", keyPath, err)
	}

	kid, err := certKid(certPEM)
	if err != nil {
		return "", fmt.Errorf("deriving kid: %w", err)
	}
	privateKey, err := parseRSAPrivateKeyPEM(keyPEM)
	if err != nil {
		return "", fmt.Errorf("parsing private key: %w", err)
	}

	tokenURL := issuer + "/protocol/openid-connect/token"
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": tokenURL,
		"jti": randomJTI(),
		"iat": now.Unix(),
		"exp": now.Add(60 * time.Second).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	assertion, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("signing client assertion: %w", err)
	}

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {scope},
	}
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("token request failed: %d %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("no access_token in response: %s", body)
	}
	return result.AccessToken, nil
}

// certKid mirrors goperator's internal/jwks.PemCertToJWK kid derivation
// exactly: sha256 of the certificate's DER bytes, truncated to 16 hex chars.
func certKid(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("no PEM block found in certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])[:16], nil
}

func parseRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PEM key is not an RSA private key")
		}
		return rsaKey, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func randomJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
