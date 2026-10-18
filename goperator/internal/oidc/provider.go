// Package oidc ports pythonoperator/src/myceliam/oidc_providers/: the
// provider-neutral interface every OIDC backend (Keycloak, Auth0, ...)
// implements, plus the factory that dispatches on config.Settings.OidcProvider.
package oidc

import (
	"context"

	"myceliam/internal/models"
)

// Provider is the interface every OIDC provider (Keycloak, Auth0, ...)
// implements — the Go equivalent of oidc_providers/base.py's OidcProvider
// Protocol. tenantID is a provider-neutral stand-in for whatever isolation
// unit a provider uses per namespace — for Keycloak, a realm. Auth0 has no
// equivalent per-namespace container: an Auth0 tenant is a pre-existing,
// whole-tenant prerequisite (the same category as "you already have a
// Keycloak server running"), not something the operator creates per
// namespace — see EnsureAccessScope/IssuerURL's own doc comments. Callers
// pass a ServiceAccount's namespace (folded with the cluster ID, see
// models.RealmForNamespace) as tenantID; what a provider does with it is its
// own business.
//
// Implementations satisfy this structurally (Go interfaces, unlike Python's
// Protocol, need no explicit inheritance) — see keycloak.KeycloakProvider and
// auth0.Provider, neither of which imports this package.
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

	// EnsureSignedjwtClient returns (clientID, actualKid). kid is a hint —
	// the caller's own self-derived value (jwks.PemCertToJWK(certPEM).Kid,
	// already embedded in jwksString) — which a provider is free to ignore:
	// Keycloak echoes it straight back, since it never reassigns the
	// JWKS's own kid; Auth0 (which computes its own kid independently, per
	// the JWK Thumbprint standard, RFC 7638) ignores the hint and returns
	// whatever its own credential-registration API response actually
	// reports instead. Callers must persist actualKid, not the hint, since
	// only actualKid is guaranteed correct for every provider. certPEM is
	// the same certificate jwksString was derived from, passed through
	// separately for Auth0: its POST /clients/{id}/credentials endpoint
	// takes a raw PEM certificate ("pem" field), not a JWKS document —
	// confirmed live against a real tenant, since jwksString has no way to
	// reconstruct the original certificate bytes. Keycloak ignores it.
	EnsureSignedjwtClient(ctx context.Context, spec *models.ClientSpec, certPEM []byte, jwksString, kid string) (clientID, actualKid string, err error)

	DeleteClient(ctx context.Context, tenantID, clientName string) error

	// IssuerURL returns an error for providers where deriving it can genuinely
	// fail (or isn't implemented yet) — a deliberate deviation from
	// base.py's issuer_url(self, tenant_id: str) -> str, which relies on
	// Python's implicit exceptions to cover the same case. One issuer per
	// tenantID regardless of cloud — both Keycloak (one issuer per realm)
	// and Auth0 (one issuer per tenant) work this way.
	IssuerURL(tenantID string) (string, error)

	// EnsureAccessScope ensures clientName can obtain a token carrying
	// audience, under scopeName. Returns azpValue: the value clientName's
	// issued tokens actually carry as their client-identifying claim (azp
	// for Keycloak, fixed to clientName by construction, so Keycloak just
	// returns clientName back). Auth0 has no
	// custom-client_id support, so its tokens' azp is its own
	// dynamically-assigned client_id instead — resolved here anyway, since
	// EnsureAccessScope already looks it up internally (see
	// auth0.Provider.resolveClientID) and returning it spares the caller a
	// second live lookup.
	//
	// Callers need this because AWS STS's OIDC federation folds azp into its
	// own `:aud` policy-context key whenever the token carries azp — even
	// when the raw aud claim is a single string, not just the multi-valued
	// case Keycloak's own azp/subjectClaim convention already accounts for
	// (confirmed live against a real Auth0-issued token: single-string aud,
	// azp still overrides it). cloudaws.EnsureRoleTrust/EnsureIdp must know
	// this value to accept it, for a provider (Auth0) whose azp otherwise has
	// no relationship at all to clientName or audience.
	EnsureAccessScope(ctx context.Context, tenantID, clientName, scopeName, audience string) (azpValue string, err error)

	// DeleteAccessScope undoes EnsureAccessScope for clientName specifically.
	// For a provider where scopeName identifies an object disposable on its
	// own (Keycloak: a per-SA client scope), clientName may be ignored and
	// the object deleted outright. For a provider where scopeName/audience
	// identifies something shared across multiple clients (Auth0: a
	// Resource Server shared by every SA in a namespace requesting that
	// cloud), only clientName's own access is revoked — the shared object
	// itself is torn down, if ever, once nothing references it any longer.
	DeleteAccessScope(ctx context.Context, tenantID, clientName, scopeName string) error

	// GetOperatorToken returns a token for the operator's own pre-provisioned
	// identity, to be exchanged for cloud credentials via AWS/GCP STS.
	GetOperatorToken(ctx context.Context) (string, error)
}
