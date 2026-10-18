package auth0

import (
	"context"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"myceliam/internal/config"
	"myceliam/internal/httpx"
	"myceliam/internal/k8shelpers"
	"myceliam/internal/operr"
)

// tokenExpiryBuffer mirrors keycloak/adminauth.go's own buffer.
const tokenExpiryBuffer = 10 * time.Second

// managementAPIAudience is Auth0's reserved identifier for its own
// Management API — every operator-bootstrap token request targets this
// fixed audience, unlike a workload token's per-(cloud,namespace) one.
// baseURL is the full "https://{domain}" (or, in tests, a plain-http
// httptest.Server URL).
func managementAPIAudience(baseURL string) string {
	return baseURL + "/api/v2/"
}

// AdminSecretName (Opaque, key "client-secret") and AdminKeypairSecretName
// (kubernetes.io/tls, tls.crt/tls.key only) are the two well-known Secrets
// New looks for in Settings.SystemNamespace, mirroring
// keycloak.AdminSecretName/AdminKeypairSecretName's exact secret-or-keypair
// auto-detection (keypair wins if both exist) — a natural fit since Auth0's
// Management API token request has the same client_credentials shape
// Keycloak's admin token request does.
const (
	AdminSecretName        = "myceliam-auth0-secret"
	AdminKeypairSecretName = "myceliam-auth0-keypair"
)

// tokenSource obtains a fresh access token for the operator's one Auth0
// Application. audience is explicit on every call — unlike Keycloak's scope-
// >audience-mapper indirection, Auth0's client_credentials grant always
// names its target audience directly. The same source backs both the
// Management API token (audience managementAPIAudience(baseURL)) and the
// operator's own cloud-federation token (audience
// Settings.Auth0OperatorAudience) — see Provider.auth/.operatorAuth.
type tokenSource interface {
	fetchToken(ctx context.Context, audience string) (accessToken string, expiresIn int, err error)
}

// adminAuth caches an access token for one fixed audience, refreshing via
// source once within tokenExpiryBuffer of expiry — same shape as
// keycloak.adminAuth. Provider holds two of these, sharing the same
// underlying source/credential, one per audience.
type adminAuth struct {
	source   tokenSource
	audience string

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func newAdminAuth(source tokenSource, audience string) *adminAuth {
	return &adminAuth{source: source, audience: audience}
}

func (a *adminAuth) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.token != "" && time.Now().Before(a.expiresAt) {
		return a.token, nil
	}

	token, expiresIn, err := a.source.fetchToken(ctx, a.audience)
	if err != nil {
		return "", err
	}
	a.token = token
	a.expiresAt = time.Now().Add(time.Duration(expiresIn)*time.Second - tokenExpiryBuffer)
	return token, nil
}

// buildTokenSource implements the secret-or-keypair auto-detection described
// on AdminSecretName/AdminKeypairSecretName above, reusing the same
// k8shelpers.ReadSecretKeyIfPresent helper keycloak.buildTokenSource uses.
func buildTokenSource(ctx context.Context, k8sClient client.Client, settings *config.Settings, baseURL string) (tokenSource, error) {
	ns := settings.SystemNamespace

	_, found, err := k8shelpers.ReadSecretKeyIfPresent(ctx, k8sClient, ns, AdminKeypairSecretName, corev1.TLSCertKey)
	if err != nil {
		return nil, err
	}
	if found {
		keyPEM, keyFound, err := k8shelpers.ReadSecretKeyIfPresent(ctx, k8sClient, ns, AdminKeypairSecretName, corev1.TLSPrivateKeyKey)
		if err != nil {
			return nil, err
		}
		if !keyFound {
			return nil, operr.Permanentf("Secret '%s/%s' has a %s but no %s", ns, AdminKeypairSecretName, corev1.TLSCertKey, corev1.TLSPrivateKeyKey)
		}
		if settings.Auth0OperatorKeypairKid == "" {
			return nil, operr.Permanentf(
				"MYCELIAM_AUTH0_OPERATOR_KEYPAIR_KID is required when using %s — unlike "+
					"Keycloak's single-certificate mode, Auth0 assigns its own kid to an "+
					"uploaded credential (shown in the Auth0 dashboard when you register it) "+
					"and there is no way for the operator to derive or look it up itself before "+
					"it can authenticate at all.",
				AdminKeypairSecretName,
			)
		}
		return newSignedJWTSource(baseURL, settings.Auth0OperatorClientID, settings.Auth0OperatorKeypairKid, keyPEM)
	}

	clientSecret, found, err := k8shelpers.ReadSecretKeyIfPresent(ctx, k8sClient, ns, AdminSecretName, "client-secret")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, operr.Permanentf(
			"Neither secret '%s/%s' (kubernetes.io/tls keypair) nor '%s/%s' "+
				"(Opaque, 'client-secret' key) exists — the operator needs one of "+
				"these in namespace %q to authenticate to Auth0's Management API.",
			ns, AdminKeypairSecretName, ns, AdminSecretName, ns,
		)
	}
	return &secretSource{
		domain:       baseURL,
		clientID:     settings.Auth0OperatorClientID,
		clientSecret: string(clientSecret),
		httpClient:   httpx.NewClient(true),
	}, nil
}
