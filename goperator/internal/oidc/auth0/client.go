// Package auth0 implements oidc.Provider against Auth0's Management API.
//
// Auth0's model was explored live against a real trial tenant before this
// package was written (see cloudmodels.Auth0ServiceAccountClaim's doc
// comment for the headline finding). Confirmed facts this package relies on:
//   - Auth0 has no per-namespace container object — the tenant itself is a
//     pre-existing, admin-provisioned prerequisite, EnsureTenant/DeleteTenant
//     are no-ops.
//   - Auth0's issuer/JWKS are tenant-*global*, not per-namespace: every
//     token, regardless of audience, is signed by the same
//     https://{domain}/.well-known/jwks.json and carries the same iss.
//     IssuerURL therefore ignores its tenantID param entirely, and a plain
//     auth0-backed client with no cloud-access-profile label works fine, no
//     artificial restriction needed.
//   - Auth0 does NOT support a custom client_id (confirmed empirically).
//     Rather than relying on Auth0's own azp claim (which does carry the
//     client_id cleanly, confirmed via a real issued token, but isn't
//     knowable until *after* the Application is created), myceliam
//     self-issues its own identity claim instead: client_metadata is set on
//     the Application (cluster_id, namespace, service_account, and an
//     incrementally-accumulated comma-separated cloud list — see
//     EnsureAccessScope), and a tenant-wide Auth0 Action bound to the
//     credentials-exchange trigger projects
//     cloudmodels.Auth0ServiceAccountClaim from it into every issued access
//     token. This mirrors Keycloak's own audience-mapper move — not relying
//     on a provider's default claims, minting one under myceliam's control
//     instead — and restores the same "known before any provider API call"
//     property Keycloak (azp=SA name) has, which relying on Auth0's own azp
//     would not.
//
// This Action is provisioned by EnsureTenant itself, lazily and idempotently
// on first use — safe to auto-create because it's a no-op for any client
// without myceliam's client_metadata keys set, so it carries none of the
// "affects every other client_credentials exchange in the tenant" risk a
// more invasive tenant-wide change would. See actions.go.
//
// Confirmed end to end this session against a real tenant: a real issued
// token carried myceliam_service_account (and its namespace/cluster_id/cloud
// siblings) with exactly the values written to client_metadata, via an
// Action created and bound exactly as actions.go
// does it — the one item flagged as unverified when this package was first
// written ("event.client.metadata inside this specific trigger") is now
// confirmed correct.
//
// A few remaining specifics are still marked "TODO: verify against a live
// tenant" — written from Auth0's documented Management API behavior, not
// the same level of exhaustive live verification the rest of this package
// went through. Confirm each flagged spot before relying on this in
// production.
package auth0

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"myceliam/internal/config"
	"myceliam/internal/httpx"
	"myceliam/internal/operr"
)

// adminCallDelay mirrors keycloak's own admin-call retry delay.
const adminCallDelay = 15 * time.Second

type Provider struct {
	settings *config.Settings
	// baseURL is the full "https://{domain}" base — stored with its scheme
	// (rather than a bare domain) specifically so tests can point it at a
	// plain-http httptest.Server, same reasoning as keycloak.KeycloakProvider's baseURL.
	baseURL    string
	auth       *adminAuth
	httpClient *http.Client

	// operatorAuth caches a token for Settings.Auth0OperatorAudience,
	// sharing auth's underlying credential (built once in New) but a
	// separate audience — the operator's own AWS/GCP cloud-federation
	// identity, distinct from Management API access. See GetOperatorToken.
	operatorAuth *adminAuth

	// actionEnsured caches ensureAction's *success* so a steady-state
	// operator only verifies/creates the tenant-wide Action once per process
	// lifetime, not on every SA's reconcile (EnsureTenant is called on every
	// one of those) — see actions.go. Deliberately not a sync.Once: a
	// transient failure (e.g. a retryable *operr.Temporary from doRequest)
	// must not be cached, or it would never be retried on a later reconcile.
	actionMu      sync.Mutex
	actionEnsured bool

	// operatorScopeEnsured caches ensureOperatorAccessScope's success, same
	// reasoning/shape as actionEnsured.
	operatorScopeMu      sync.Mutex
	operatorScopeEnsured bool
}

// New builds a Provider, auto-detecting the operator's own Management API
// credential the same way keycloak.NewProvider does — see buildTokenSource.
func New(ctx context.Context, settings *config.Settings, k8sClient client.Client) (*Provider, error) {
	baseURL := "https://" + strings.TrimRight(settings.Auth0Domain, "/")
	source, err := buildTokenSource(ctx, k8sClient, settings, baseURL)
	if err != nil {
		return nil, err
	}
	return &Provider{
		settings:     settings,
		baseURL:      baseURL,
		auth:         newAdminAuth(source, managementAPIAudience(baseURL)),
		operatorAuth: newAdminAuth(source, settings.Auth0OperatorAudience),
		httpClient:   httpx.NewClient(true),
	}, nil
}

// doRequest performs one Auth0 Management API call against
// {baseURL}/api/v2/<path>, decoding the JSON response body into out (ignored
// if nil). Returns an *operr.Temporary for any transport/non-2xx failure,
// same uniform-retry stance as keycloak.
func (p *Provider) doRequest(ctx context.Context, method, path string, body, out any) error {
	token, err := p.auth.Token(ctx)
	if err != nil {
		return err
	}

	var reqBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding Auth0 API request body for %s %s: %w", method, path, err)
		}
		reqBody = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.baseURL+"/api/v2"+path, reqBody)
	if err != nil {
		return fmt.Errorf("building Auth0 API request for %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return operr.Temporaryf(adminCallDelay, "Error calling Auth0 API %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return operr.Temporaryf(adminCallDelay, "Auth0 API %s %s returned %s: %s", method, path, resp.Status, strings.TrimSpace(string(respBody)))
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decoding Auth0 API response for %s %s: %w", method, path, err)
		}
	}
	return nil
}

// EnsureTenant has no per-namespace container object to create — tenantID
// itself is ignored — but does ensure the one tenant-wide Action every
// myceliam Application depends on exists, cached after the first success so
// later calls (one per SA reconcile) are free. See actions.go.
func (p *Provider) EnsureTenant(ctx context.Context, tenantID string) error {
	p.actionMu.Lock()
	defer p.actionMu.Unlock()
	if p.actionEnsured {
		return nil
	}
	if err := p.ensureAction(ctx); err != nil {
		return err
	}
	p.actionEnsured = true
	return nil
}

// DeleteTenant leaves the tenant-wide Action alone — other namespaces'
// Applications still depend on it — but does force-delete the two Resource
// Servers (and any Client Grants against them) namespace-scoped to tenantID:
// "aws-"+tenantID and "gcp-"+tenantID, tenantID itself already being
// "<clusterID>-<namespace>" (see models.RealmForNamespace, which is what
// NamespaceReconciler actually passes here) folded into
// cloudmodels.ParseCloudFederationSpecs's "<cloud>-<clusterID>-<namespace>"
// shared-audience convention.
//
// This exists because, unlike Keycloak's realm, Auth0 has no single
// namespace-wide container whose deletion would cascade this away — normal
// cleanup relies entirely on each ServiceAccount's own finalizer-triggered
// DeleteAccessScope call happening to be the last one out (see its own doc
// comment). Confirmed live: when that per-SA path doesn't run for every SA
// that ever referenced a namespace's Resource Server (a stuck/force-deleted
// ServiceAccount, say), the Resource Server orphans forever, since nothing
// else ever revisits it. This sweep makes namespace deletion just as robust
// as Keycloak's realm delete regardless of any individual SA's own cleanup
// history — safe unconditionally, since by namespace-delete time nothing in
// that namespace can legitimately still need either Resource Server.
func (p *Provider) DeleteTenant(ctx context.Context, tenantID string) error {
	if err := p.deleteResourceServerAndGrants(ctx, "aws-"+tenantID); err != nil {
		return err
	}
	return p.deleteResourceServerAndGrants(ctx, "gcp-"+tenantID)
}

// IssuerURL ignores tenantID: Auth0's issuer is tenant-global, not
// per-namespace — see package doc comment.
func (p *Provider) IssuerURL(tenantID string) (string, error) {
	return p.baseURL + "/", nil
}

// GetOperatorToken fetches a client_credentials token for the operator's own
// Auth0 Application against Settings.Auth0OperatorAudience — the operator's
// AWS/GCP cloud-federation identity, kept separate from Management API
// access (auth/managementAPIAudience above) exactly the way Keycloak's
// operatorAuth is kept separate from its admin-scoped auth despite sharing
// one credential. Unlike Keycloak's admin-provisioned client scope, the
// Resource Server + Client Grant this audience needs are provisioned by the
// operator itself, lazily and idempotently, the first time this is called
// (see ensureOperatorAccessScope) — consistent with this package's existing
// stance that everything Auth0 lets the Management API create, myceliam
// creates itself rather than asking an admin to pre-provision it.
func (p *Provider) GetOperatorToken(ctx context.Context) (string, error) {
	if p.settings.Auth0OperatorAudience == "" {
		return "", operr.Permanentf(
			"MYCELIAM_AUTH0_OPERATOR_AUDIENCE is required to use Auth0 for the operator's own " +
				"cloud-federation token — set MYCELIAM_OPERATOR_PROVIDER=spiffe instead if " +
				"this deployment has no dedicated operator-bootstrap Auth0 API.",
		)
	}
	if err := p.ensureOperatorAccessScope(ctx); err != nil {
		return "", err
	}
	return p.operatorAuth.Token(ctx)
}
