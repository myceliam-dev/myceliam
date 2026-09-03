// Package oidc ports pythonoperator/src/myceliam/oidc_providers/: the
// provider-neutral interface every OIDC backend (Keycloak, Okta, ...)
// implements, plus the factory that dispatches on config.Settings.OidcProvider.
package oidc

import (
	"context"

	"myceliam/internal/models"
)

// Provider is the interface every OIDC provider (Keycloak, Okta, ...)
// implements — the Go equivalent of oidc_providers/base.py's OidcProvider
// Protocol. tenantID is a provider-neutral stand-in for whatever isolation
// unit a provider uses per namespace — a Keycloak realm, an Okta org, etc.
// Callers pass a ServiceAccount's namespace as tenantID; what a provider does
// with it is its own business.
//
// Implementations satisfy this structurally (Go interfaces, unlike Python's
// Protocol, need no explicit inheritance) — see keycloak.KeycloakProvider and
// okta.Provider, neither of which imports this package.
type Provider interface {
	EnsureTenant(ctx context.Context, tenantID string) error

	// DeleteTenant deletes the tenant itself (e.g. a Keycloak realm). No-op if
	// it doesn't exist. Called when the Kubernetes namespace it's derived from
	// is deleted — at that point no ServiceAccount can ever reference it
	// again, so unlike DeleteClient (one SA) this tears down the whole
	// per-namespace tenant, not just one client within it.
	DeleteTenant(ctx context.Context, tenantID string) error

	// EnsureSecretClient returns (clientID, clientSecret).
	EnsureSecretClient(ctx context.Context, spec *models.ClientSpec) (clientID, clientSecret string, err error)

	// EnsureSignedjwtClient returns clientID.
	EnsureSignedjwtClient(ctx context.Context, spec *models.ClientSpec, jwksString string) (clientID string, err error)

	DeleteClient(ctx context.Context, tenantID, clientName string) error

	// IssuerURL returns an error for providers where deriving it can genuinely
	// fail (or isn't implemented yet) — a deliberate deviation from
	// base.py's issuer_url(self, tenant_id: str) -> str, which relies on
	// Python's implicit exceptions to cover the same case.
	IssuerURL(tenantID string) (string, error)

	// EnsureAccessScope ensures clientName can obtain a token carrying
	// audience, under scopeName.
	EnsureAccessScope(ctx context.Context, tenantID, clientName, scopeName, audience string) error

	DeleteAccessScope(ctx context.Context, tenantID, scopeName string) error

	// GetOperatorToken returns a token for the operator's own pre-provisioned
	// identity, to be exchanged for cloud credentials via AWS/GCP STS.
	GetOperatorToken(ctx context.Context) (string, error)
}
