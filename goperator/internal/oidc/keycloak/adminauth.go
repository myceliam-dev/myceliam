package keycloak

import (
	"context"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"
)

// tokenExpiryBuffer is subtracted from a fetched token's reported expiry so a
// concurrent reconcile never starts a multi-step admin sequence with a token
// that expires mid-flight.
const tokenExpiryBuffer = 10 * time.Second

// tokenSource obtains a fresh access token for the operator's one Keycloak
// identity — the two implementations are gocloakSecretSource
// (client_credentials via a client secret) and *signedJWTSource (RFC 7523
// client assertion). The same source backs both the admin-scoped token
// (scope "") and the operator's own cloud-federation token (scope
// Settings.KeycloakOperatorScope) — see KeycloakProvider.auth/.operatorAuth.
type tokenSource interface {
	fetchToken(ctx context.Context, scope string) (accessToken string, expiresIn int, err error)
}

// tokenProvider is the interface KeycloakProvider depends on for admin
// tokens — satisfied by *adminAuth, and by fakes in tests.
type tokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// adminAuth caches an access token for one fixed scope, refreshing via
// source once it's within tokenExpiryBuffer of expiry. Mirrors
// python-keycloak's KeycloakOpenIDConnection expiry-tracking
// (self.token/self.expires_at), but as a small standalone cache rather than
// base-class machinery, since gocloak has no equivalent connection object to
// hook into. KeycloakProvider holds two of these — one per scope — sharing
// the same underlying source/credential.
type adminAuth struct {
	source tokenSource
	scope  string

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func newAdminAuth(source tokenSource, scope string) *adminAuth {
	return &adminAuth{source: source, scope: scope}
}

func (a *adminAuth) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.token != "" && time.Now().Before(a.expiresAt) {
		return a.token, nil
	}

	token, expiresIn, err := a.source.fetchToken(ctx, a.scope)
	if err != nil {
		return "", err
	}
	a.token = token
	a.expiresAt = time.Now().Add(time.Duration(expiresIn)*time.Second - tokenExpiryBuffer)
	return token, nil
}

// gocloakSecretSource authenticates via client_credentials + a client secret
// — the default (myceliam-keycloak-secret present) auth path.
type gocloakSecretSource struct {
	gc           *gocloak.GoCloak
	clientID     string
	clientSecret string
	realm        string
}

func (s *gocloakSecretSource) fetchToken(ctx context.Context, scope string) (string, int, error) {
	options := gocloak.TokenOptions{
		GrantType:    gocloak.StringP("client_credentials"),
		ClientID:     gocloak.StringP(s.clientID),
		ClientSecret: gocloak.StringP(s.clientSecret),
	}
	if scope != "" {
		options.Scope = gocloak.StringP(scope)
	}
	token, err := s.gc.GetToken(ctx, s.realm, options)
	if err != nil {
		return "", 0, err
	}
	return token.AccessToken, token.ExpiresIn, nil
}
