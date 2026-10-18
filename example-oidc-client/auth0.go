// auth0.go implements Auth0's two client_credentials variants for this demo
// app — client_secret_post and private_key_jwt — each requesting a single
// Resource Server audience per call, mirroring goperator's
// internal/oidc/auth0/signedjwt.go (same token-endpoint shape, since this is
// a real Auth0 tenant, not a mock).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func auth0TokenEndpoint(domain string) string {
	return "https://" + domain + "/oauth/token"
}

func getAuth0TokenSecret(ctx context.Context, domain, clientID, clientSecret, audience string) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"audience":      {audience},
	}
	return postAuth0TokenRequest(ctx, domain, form)
}

// getAuth0TokenSignedJWT authenticates via RFC 7523 private_key_jwt. Unlike
// getKeycloakTokenSignedJWT's certKid (self-derived, since Keycloak echoes
// back whatever kid this ServiceAccount's own JWKS push used), kid here is
// NOT derived from the certificate: Auth0 assigns its own kid to a
// registered credential (RFC 7638 JWK Thumbprint), unknowable until after
// registration — it's read from the AUTH0_KID env var instead, sourced from
// the <sa>-jwt-auth0-metadata secret the operator wrote.
func getAuth0TokenSignedJWT(ctx context.Context, domain, clientID, kid, certPath, keyPath, audience string) (string, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("reading key %s: %w", keyPath, err)
	}
	privateKey, err := parseRSAPrivateKeyPEM(keyPEM)
	if err != nil {
		return "", fmt.Errorf("parsing private key: %w", err)
	}

	tokenURL := auth0TokenEndpoint(domain)
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
	//fmt.Println("token:", token)
	token.Header["kid"] = kid
	assertion, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("signing client assertion: %w", err)
	}

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"audience":              {audience},
	}
	return postAuth0TokenRequest(ctx, domain, form)
}

func postAuth0TokenRequest(ctx context.Context, domain string, form url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, auth0TokenEndpoint(domain), strings.NewReader(form.Encode()))
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
