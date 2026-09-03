// Package keycloak ports pythonoperator/src/myceliam/oidc_providers/keycloak/:
// the Keycloak implementation of oidc.Provider. tenantID maps 1:1 to a
// Keycloak realm.
//
// All operations are idempotent: callers can invoke them on every reconcile
// without creating duplicates.
package keycloak

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"myceliam/internal/config"
	"myceliam/internal/httpx"
	"myceliam/internal/k8shelpers"
	"myceliam/internal/models"
	"myceliam/internal/operr"
)

// adminCallDelay is the retry delay used for every Keycloak Admin API
// failure, matching pythonoperator's uniform delay=15 across client.py/scope.py.
const adminCallDelay = 15 * time.Second

// AdminSecretName (Opaque, key "client-secret") and AdminKeypairSecretName
// (kubernetes.io/tls, keys tls.crt/tls.key — nothing else, so it stays
// compatible with cert-manager or any other standard TLS rotation tooling)
// are the two well-known Secrets NewProvider looks for, in
// Settings.SystemNamespace, to authenticate the operator's one Keycloak
// identity (Settings.KeycloakClientID) — used both for the Admin REST API
// and for the operator's own cloud-federation token (GetOperatorToken).
// Unlike clienttype=signedjwt workload apps, the operator never generates a
// keypair for itself: it only ever reads whichever of these an admin has
// already placed in the cluster. If both exist, the keypair wins.
//
// For AdminKeypairSecretName, the admin must have already uploaded this
// exact certificate (X.509 PEM) directly to the Keycloak client's
// Credentials tab ("Signed Jwt" authenticator, single certificate — not a
// JWKS URL). No separate JWKS conversion step needed, and no kid either:
// see newSignedJWTSource's doc comment for why.
const (
	AdminSecretName        = "myceliam-keycloak-secret"
	AdminKeypairSecretName = "myceliam-keycloak-keypair"
)

type KeycloakProvider struct {
	settings     *config.Settings
	admin        AdminAPI
	auth         tokenProvider
	operatorAuth tokenProvider

	// httpClient is used by signedJWTSource.fetchToken (its own client, see
	// signedjwt.go).
	httpClient *http.Client
}

// NewProvider builds a KeycloakProvider from Settings, mirroring client.py's
// KeycloakProvider.__init__ / _build_admin_connection. k8sClient is used
// only to look up the operator's own credential Secret (see
// AdminSecretName/AdminKeypairSecretName) — a direct, uncached client is
// fine since this is a one-time read at startup.
func NewProvider(ctx context.Context, settings *config.Settings, k8sClient client.Client) (*KeycloakProvider, error) {
	gc := gocloak.NewClient(settings.KeycloakURL)
	if !settings.KeycloakVerifySSL {
		gc.RestyClient().SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // opt-in via MYCELIAM_KEYCLOAK_VERIFY_SSL=false
	}

	source, err := buildTokenSource(ctx, k8sClient, settings, gc)
	if err != nil {
		return nil, err
	}

	return &KeycloakProvider{
		settings:     settings,
		admin:        newGocloakAdmin(gc, settings.KeycloakURL),
		auth:         newAdminAuth(source, ""),
		operatorAuth: newAdminAuth(source, settings.KeycloakOperatorScope),
		httpClient:   httpx.NewClient(settings.KeycloakVerifySSL),
	}, nil
}

// buildTokenSource implements the secret auto-detection described on
// AdminSecretName/AdminKeypairSecretName above, reusing
// k8shelpers.ReadSecretKeyIfPresent — the same helper clienttype=signedjwt
// apps use to read their own <sa-name>-oidc-credentials secret.
func buildTokenSource(ctx context.Context, k8sClient client.Client, settings *config.Settings, gc *gocloak.GoCloak) (tokenSource, error) {
	ns := settings.SystemNamespace

	// The cert itself is only needed to detect that this Secret exists and is
	// complete — it's never read for its content: the admin uploads it
	// directly to the Keycloak client's Credentials tab (Signed Jwt
	// authenticator, single certificate, no JWKS involved), and Keycloak's
	// single-certificate mode needs no kid from the assertion at all (see
	// newSignedJWTSource's doc comment).
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
		return newSignedJWTSource(
			settings.KeycloakURL,
			settings.KeycloakClientID,
			settings.KeycloakAdminRealm,
			settings.KeycloakVerifySSL,
			keyPEM,
			time.Duration(settings.KeycloakAdminSignedjwtAssertionLifetimeSeconds)*time.Second,
		)
	}

	clientSecret, found, err := k8shelpers.ReadSecretKeyIfPresent(ctx, k8sClient, ns, AdminSecretName, "client-secret")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, operr.Permanentf(
			"Neither secret '%s/%s' (kubernetes.io/tls keypair) nor '%s/%s' "+
				"(Opaque, 'client-secret' key) exists — the operator needs one "+
				"of these in namespace %q to authenticate to Keycloak.",
			ns, AdminKeypairSecretName, ns, AdminSecretName, ns,
		)
	}
	return &gocloakSecretSource{
		gc:           gc,
		clientID:     settings.KeycloakClientID,
		clientSecret: string(clientSecret),
		realm:        settings.KeycloakAdminRealm,
	}, nil
}

// verifyClusterOwnership refuses (as an *operr.Permanent) to touch a realm/
// client that either lacks ClusterIDAttribute entirely or carries a
// different cluster's value — see ClusterIDAttribute's own doc comment. A
// missing attribute is treated the same as a mismatch: every myceliam-managed
// realm/client is stamped at creation from here on, so one that isn't either
// predates this feature or was created out-of-band, and either way its
// provenance isn't something this cluster should assume it owns.
func verifyClusterOwnership(kind, name string, attrs map[string]string, clusterID string) error {
	owner, stamped := attrs[ClusterIDAttribute]
	if stamped && owner == clusterID {
		return nil
	}
	if !stamped {
		return operr.Permanentf(
			"%s '%s' exists but has no '%s' attribute — refusing to manage a "+
				"%s of unknown provenance rather than silently adopting it.",
			kind, name, ClusterIDAttribute, kind,
		)
	}
	return operr.Permanentf(
		"%s '%s' is owned by cluster '%s', not this cluster ('%s') — refusing "+
			"to modify a %s belonging to a different cluster.",
		kind, name, owner, clusterID, kind,
	)
}

func (p *KeycloakProvider) EnsureTenant(ctx context.Context, tenantID string) error {
	token, err := p.auth.Token(ctx)
	if err != nil {
		return err
	}
	exists, attrs, err := p.admin.RealmExists(ctx, token, tenantID)
	if err != nil {
		return operr.Temporaryf(adminCallDelay, "Error checking realm '%s': %v", tenantID, err)
	}
	if exists {
		return verifyClusterOwnership("realm", tenantID, attrs, p.settings.ClusterID)
	}
	if err := p.admin.CreateRealm(ctx, token, tenantID, p.settings.ClusterID); err != nil {
		return operr.Temporaryf(adminCallDelay, "Error creating realm '%s': %v", tenantID, err)
	}
	return nil
}

func (p *KeycloakProvider) DeleteTenant(ctx context.Context, tenantID string) error {
	token, err := p.auth.Token(ctx)
	if err != nil {
		return err
	}
	exists, attrs, err := p.admin.RealmExists(ctx, token, tenantID)
	if err != nil {
		return operr.Temporaryf(adminCallDelay, "Error checking realm '%s' before delete: %v", tenantID, err)
	}
	if !exists {
		return nil
	}
	if err := verifyClusterOwnership("realm", tenantID, attrs, p.settings.ClusterID); err != nil {
		return err
	}
	if err := p.admin.DeleteRealm(ctx, token, tenantID); err != nil {
		return operr.Temporaryf(adminCallDelay, "Error deleting realm '%s': %v", tenantID, err)
	}
	return nil
}

// EnsureSecretClient ensures a client-credentials (client-secret) client
// exists. Returns (clientID, clientSecret).
func (p *KeycloakProvider) EnsureSecretClient(ctx context.Context, spec *models.ClientSpec) (string, string, error) {
	token, err := p.auth.Token(ctx)
	if err != nil {
		return "", "", err
	}
	realm := spec.Realm

	payload := ClientPayload{
		ClientID:                  spec.ClientName,
		Enabled:                   true,
		Protocol:                  "openid-connect",
		PublicClient:              false,
		ServiceAccountsEnabled:    true,
		StandardFlowEnabled:       false,
		DirectAccessGrantsEnabled: false,
		ClientAuthenticatorType:   "client-secret",
		Attributes:                map[string]string{ClusterIDAttribute: p.settings.ClusterID},
	}

	internalID, attrs, found, err := p.admin.FindClient(ctx, token, realm, spec.ClientName)
	if err != nil {
		return "", "", operr.Temporaryf(adminCallDelay, "Error provisioning secret client '%s' in realm '%s': %v", spec.ClientName, realm, err)
	}
	if !found {
		internalID, err = p.admin.CreateClient(ctx, token, realm, payload)
	} else if err := verifyClusterOwnership("client", spec.ClientName, attrs, p.settings.ClusterID); err != nil {
		return "", "", err
	} else {
		err = p.admin.UpdateClient(ctx, token, realm, internalID, payload)
	}
	if err != nil {
		return "", "", operr.Temporaryf(adminCallDelay, "Error provisioning secret client '%s' in realm '%s': %v", spec.ClientName, realm, err)
	}
	if err := demoteDefaultScopesToOptional(ctx, p.admin, token, realm, internalID); err != nil {
		return "", "", operr.Temporaryf(adminCallDelay, "Error demoting default scopes for client '%s' in realm '%s': %v", spec.ClientName, realm, err)
	}

	secret, ok, err := p.admin.ClientSecret(ctx, token, realm, internalID)
	if err != nil {
		return "", "", operr.Temporaryf(adminCallDelay, "Error provisioning secret client '%s' in realm '%s': %v", spec.ClientName, realm, err)
	}
	if !ok {
		secret, err = p.admin.GenerateClientSecret(ctx, token, realm, internalID)
		if err != nil {
			return "", "", operr.Temporaryf(adminCallDelay, "Error provisioning secret client '%s' in realm '%s': %v", spec.ClientName, realm, err)
		}
	}

	return spec.ClientName, secret, nil
}

// EnsureSignedjwtClient ensures a signed-JWT (private_key_jwt) client exists
// with the given JWKS. Returns clientID.
func (p *KeycloakProvider) EnsureSignedjwtClient(ctx context.Context, spec *models.ClientSpec, jwksString string) (string, error) {
	token, err := p.auth.Token(ctx)
	if err != nil {
		return "", err
	}
	realm := spec.Realm

	payload := ClientPayload{
		ClientID:                  spec.ClientName,
		Enabled:                   true,
		Protocol:                  "openid-connect",
		PublicClient:              false,
		ServiceAccountsEnabled:    true,
		StandardFlowEnabled:       false,
		DirectAccessGrantsEnabled: false,
		ClientAuthenticatorType:   "client-jwt",
		Attributes: map[string]string{
			"use.jwks.string":                 "true",
			"jwks.string":                     jwksString,
			"token.endpoint.auth.signing.alg": "RS256",
			ClusterIDAttribute:                p.settings.ClusterID,
		},
	}

	internalID, attrs, found, err := p.admin.FindClient(ctx, token, realm, spec.ClientName)
	if err != nil {
		return "", operr.Temporaryf(adminCallDelay, "Error provisioning signedjwt client '%s' in realm '%s': %v", spec.ClientName, realm, err)
	}
	if !found {
		internalID, err = p.admin.CreateClient(ctx, token, realm, payload)
	} else if err := verifyClusterOwnership("client", spec.ClientName, attrs, p.settings.ClusterID); err != nil {
		return "", err
	} else {
		err = p.admin.UpdateClient(ctx, token, realm, internalID, payload)
	}
	if err != nil {
		return "", operr.Temporaryf(adminCallDelay, "Error provisioning signedjwt client '%s' in realm '%s': %v", spec.ClientName, realm, err)
	}
	if err := demoteDefaultScopesToOptional(ctx, p.admin, token, realm, internalID); err != nil {
		return "", operr.Temporaryf(adminCallDelay, "Error demoting default scopes for client '%s' in realm '%s': %v", spec.ClientName, realm, err)
	}

	return spec.ClientName, nil
}

// demoteDefaultScopesToOptional moves every one of clientID's current default
// client scopes to optional. A freshly created client inherits the realm's
// default client scopes (typically profile/email/roles/web-origins/acr) —
// left as default, the "roles" scope's audience-resolve mapper silently
// injects Keycloak's own "account" client into every token's aud, turning
// what should be a clean single-value audience into an array. Idempotent: a
// scope already moved to optional is left alone (it simply won't appear in
// ClientDefaultScopeIDs again).
func demoteDefaultScopesToOptional(ctx context.Context, admin AdminAPI, token, realm, clientID string) error {
	defaultScopeIDs, err := admin.ClientDefaultScopeIDs(ctx, token, realm, clientID)
	if err != nil {
		return err
	}
	for _, scopeID := range defaultScopeIDs {
		if err := admin.DetachDefaultScope(ctx, token, realm, clientID, scopeID); err != nil {
			return err
		}
		if err := admin.AttachOptionalScope(ctx, token, realm, clientID, scopeID); err != nil {
			return err
		}
	}
	return nil
}

func (p *KeycloakProvider) DeleteClient(ctx context.Context, tenantID, clientName string) error {
	token, err := p.auth.Token(ctx)
	if err != nil {
		return err
	}
	id, attrs, found, err := p.admin.FindClient(ctx, token, tenantID, clientName)
	if err != nil {
		return operr.Temporaryf(adminCallDelay, "Error deleting client '%s' in realm '%s': %v", clientName, tenantID, err)
	}
	if !found {
		return nil
	}
	if err := verifyClusterOwnership("client", clientName, attrs, p.settings.ClusterID); err != nil {
		return err
	}
	if err := p.admin.DeleteClient(ctx, token, tenantID, id); err != nil {
		return operr.Temporaryf(adminCallDelay, "Error deleting client '%s' in realm '%s': %v", clientName, tenantID, err)
	}
	return nil
}

func (p *KeycloakProvider) IssuerURL(tenantID string) (string, error) {
	return fmt.Sprintf("%s/realms/%s", strings.TrimRight(p.settings.KeycloakURL, "/"), tenantID), nil
}

func (p *KeycloakProvider) EnsureAccessScope(ctx context.Context, tenantID, clientName, scopeName, audience string) error {
	token, err := p.auth.Token(ctx)
	if err != nil {
		return err
	}
	return ensureAccessScope(ctx, p.admin, token, tenantID, clientName, scopeName, audience)
}

func (p *KeycloakProvider) DeleteAccessScope(ctx context.Context, tenantID, scopeName string) error {
	token, err := p.auth.Token(ctx)
	if err != nil {
		return err
	}
	return deleteAccessScope(ctx, p.admin, token, tenantID, scopeName)
}

// GetOperatorToken obtains a token for the operator's own Keycloak identity
// (whichever credential NewProvider auto-detected — see AdminSecretName/
// AdminKeypairSecretName's doc comment), to be exchanged for cloud
// credentials via AWS/GCP STS. Uses the same underlying source as the admin
// connection above, just cached separately under Settings.KeycloakOperatorScope
// instead of no scope.
func (p *KeycloakProvider) GetOperatorToken(ctx context.Context) (string, error) {
	return p.operatorAuth.Token(ctx)
}
