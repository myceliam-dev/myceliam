// signedjwt.go ports pythonoperator/src/myceliam/oidc_providers/keycloak/
// signedjwt_connection.py: obtaining an admin token via an RFC 7523 JWT-bearer
// client assertion (private_key_jwt) instead of a client secret.
//
// Unlike the Python SignedJwtKeycloakOpenIDConnection — which has to override
// python-keycloak's get_token()/refresh_token() hooks to slot into
// KeycloakOpenIDConnection's existing expiry-tracking machinery — this is just
// a plain tokenSource (see adminauth.go) plugged into the same cache/refresh
// wrapper the client-secret path uses, since there's no base-class machinery
// to integrate with in the first place.
package keycloak

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

type signedJWTSource struct {
	serverURL         string
	clientID          string
	realmName         string
	privateKey        *rsa.PrivateKey
	assertionLifetime time.Duration
	httpClient        *http.Client
}

// newSignedJWTSource has no kid parameter — deliberately. Keycloak's
// client-jwt authenticator (a single admin-uploaded X.509 certificate, no
// JWKS involved) does its own key lookup with no kid needed at all, since
// there's only ever one certificate to check against; supplying a kid in the
// assertion header that doesn't match Keycloak's own internal bookkeeping
// makes it fail with "Unable to load public key" instead. Confirmed
// empirically: the identical assertion succeeds with no kid header and fails
// with one, against a real Keycloak instance. This is unrelated to
// clienttype=signedjwt workload apps, which use a completely different
// Keycloak mechanism (a JWKS array with a myceliam-chosen kid embedded in
// it, pushed via the Admin API) where kid matters and is self-consistent by
// construction — see jwks.PemCertToJWKSString/EnsureSignedjwtClient.
func newSignedJWTSource(
	serverURL, clientID, realmName string,
	verifySSL bool,
	privateKeyPEM []byte,
	assertionLifetime time.Duration,
) (*signedJWTSource, error) {
	key, err := parseRSAPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing signedjwt admin private key: %w", err)
	}
	return &signedJWTSource{
		serverURL:         strings.TrimRight(serverURL, "/"),
		clientID:          clientID,
		realmName:         realmName,
		privateKey:        key,
		assertionLifetime: assertionLifetime,
		httpClient:        httpx.NewClient(verifySSL),
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

func (s *signedJWTSource) tokenEndpoint() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", s.serverURL, s.realmName)
}

// buildClientAssertion signs a fresh assertion on every call: client_credentials
// responses never carry a refresh_token to reuse, so there's no "assertion
// still valid" state worth caching the way a longer-lived credential might.
func (s *signedJWTSource) buildClientAssertion() (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": s.clientID,
		"sub": s.clientID,
		"aud": s.tokenEndpoint(),
		"jti": ksuid.New().String(),
		"iat": now.Unix(),
		"exp": now.Add(s.assertionLifetime).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privateKey)
}

func (s *signedJWTSource) fetchToken(ctx context.Context, scope string) (string, int, error) {
	assertion, err := s.buildClientAssertion()
	if err != nil {
		return "", 0, fmt.Errorf("error building signedjwt client assertion: %w", err)
	}

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {assertion},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("error building signedjwt admin token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("error obtaining signedjwt admin token: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf(
			"error obtaining signedjwt admin token: %s — response body: %s",
			resp.Status, strings.TrimSpace(string(body)),
		)
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", 0, fmt.Errorf("error decoding signedjwt admin token response: %w", err)
	}
	return payload.AccessToken, payload.ExpiresIn, nil
}
