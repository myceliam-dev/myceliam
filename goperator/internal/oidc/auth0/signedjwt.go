// signedjwt.go implements both tokenSource variants for the operator's own
// Auth0 Management API credential — a raw client_secret POST and an RFC 7523
// private_key_jwt assertion, mirroring keycloak/adminauth.go +
// keycloak/signedjwt.go's split (not shared code — provider packages don't
// cross-import — but the same structure, since Auth0's client_credentials
// token endpoint has the identical shape).
package auth0

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/segmentio/ksuid"

	"myceliam/internal/httpx"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// assertionLifetime is fixed (unlike Keycloak's configurable
// KeycloakAdminSignedjwtAssertionLifetimeSeconds) — Phase 1 doesn't expose a
// separate setting for this, 60s is ample for a single token request.
const assertionLifetime = 60 * time.Second

// tokenEndpoint takes an already-schemed base URL (e.g. "https://your-tenant
// .us.auth0.com", or a plain-http httptest.Server URL in tests).
func tokenEndpoint(baseURL string) string {
	return baseURL + "/oauth/token"
}

// secretSource authenticates via client_credentials + a client secret — the
// default (myceliam-auth0-secret present) auth path. domain is the
// already-schemed base URL (see tokenEndpoint) despite the field name,
// kept as-is to match how buildTokenSource/adminauth.go already refer to it.
type secretSource struct {
	domain       string
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

func (s *secretSource) fetchToken(ctx context.Context, audience string) (string, int, error) {
	client := s.httpClient
	if client == nil {
		client = httpx.NewClient(true)
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {s.clientID},
		"client_secret": {s.clientSecret},
		"audience":      {audience},
	}
	return postTokenRequest(ctx, client, tokenEndpoint(s.domain), form)
}

// signedJWTSource authenticates via private_key_jwt (RFC 7523 client
// assertion). Unlike Keycloak's single-certificate client-jwt mode (which
// needs no kid at all — see keycloak/signedjwt.go's own doc comment), Auth0
// assigns its own kid to an uploaded credential; kid is required here and
// supplied via Settings.Auth0OperatorKeypairKid, not derived from the key.
type signedJWTSource struct {
	domain     string
	clientID   string
	kid        string
	privateKey *rsa.PrivateKey
	httpClient *http.Client
}

func newSignedJWTSource(domain, clientID, kid string, privateKeyPEM []byte) (*signedJWTSource, error) {
	key, err := parseRSAPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing Auth0 admin private key: %w", err)
	}
	return &signedJWTSource{
		domain:     domain,
		clientID:   clientID,
		kid:        kid,
		privateKey: key,
		httpClient: httpx.NewClient(true),
	}, nil
}

func parseRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
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

// buildClientAssertion signs a fresh assertion on every call, same reasoning
// as keycloak.signedJWTSource: client_credentials responses never carry a
// refresh_token, so there's no "assertion still valid" state worth caching.
func (s *signedJWTSource) buildClientAssertion() (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": s.clientID,
		"sub": s.clientID,
		"aud": tokenEndpoint(s.domain),
		"jti": ksuid.New().String(),
		"iat": now.Unix(),
		"exp": now.Add(assertionLifetime).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.privateKey)
}

func (s *signedJWTSource) fetchToken(ctx context.Context, audience string) (string, int, error) {
	assertion, err := s.buildClientAssertion()
	if err != nil {
		return "", 0, fmt.Errorf("error building Auth0 admin client assertion: %w", err)
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {s.clientID},
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {assertion},
		"audience":              {audience},
	}
	return postTokenRequest(ctx, s.httpClient, tokenEndpoint(s.domain), form)
}

// postTokenRequest is the shared HTTP mechanics both sources use — same
// style as keycloak.signedJWTSource.fetchToken.
func postTokenRequest(ctx context.Context, httpClient *http.Client, endpoint string, form url.Values) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("error building Auth0 admin token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("error obtaining Auth0 admin token: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf(
			"error obtaining Auth0 admin token: %s — response body: %s",
			resp.Status, strings.TrimSpace(string(body)),
		)
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", 0, fmt.Errorf("error decoding Auth0 admin token response: %w", err)
	}
	return payload.AccessToken, payload.ExpiresIn, nil
}
