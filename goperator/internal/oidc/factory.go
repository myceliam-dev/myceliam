package oidc

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"myceliam/internal/config"
	"myceliam/internal/oidc/keycloak"
	"myceliam/internal/oidc/okta"
)

// Compile-time checks that both implementations satisfy Provider structurally
// — neither keycloak nor okta imports this package (avoiding an import
// cycle), so this is the one place that can assert it.
var (
	_ Provider = (*keycloak.KeycloakProvider)(nil)
	_ Provider = (*okta.Provider)(nil)
)

// GetProvider returns nil for oidc_provider="none" — deployments that only
// ever use clienttype=spiffe ServiceAccounts and want no Keycloak/Okta/Auth0
// dependency at all. Callers that need a Provider for a non-spiffe
// ServiceAccount must handle that nil themselves (see the controller layer).
func GetProvider(ctx context.Context, settings *config.Settings, k8sClient client.Client) (Provider, error) {
	switch settings.OidcProvider {
	case "none":
		return nil, nil
	case "keycloak":
		return keycloak.NewProvider(ctx, settings, k8sClient)
	case "okta":
		return okta.New(settings), nil
	default:
		return nil, fmt.Errorf("unknown oidc_provider: %q", settings.OidcProvider)
	}
}
