package oidc

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"myceliam/internal/config"
	"myceliam/internal/oidc/auth0"
	"myceliam/internal/oidc/keycloak"
)

// Compile-time checks that every implementation satisfies Provider
// structurally — neither keycloak nor auth0 imports this package (avoiding
// an import cycle), so this is the one place that can assert it.
var (
	_ Provider = (*keycloak.KeycloakProvider)(nil)
	_ Provider = (*auth0.Provider)(nil)
)

// GetProviders builds one Provider instance per entry in
// settings.ActiveProviders() — the operator provisions workload
// ServiceAccounts against every one of these simultaneously, not a single
// globally-selected provider. An empty map is valid (a deployment that only
// ever uses clienttype=spiffe ServiceAccounts and wants no Keycloak/Auth0
// dependency at all — what oidc_provider="none" used to mean). Callers
// resolve which entry a given ServiceAccount uses via the
// myceliam.io/oidc-provider label (see the controller layer's
// resolveProviderName).
func GetProviders(ctx context.Context, settings *config.Settings, k8sClient client.Client) (map[string]Provider, error) {
	providers := make(map[string]Provider)
	for _, name := range settings.ActiveProviders() {
		var (
			p   Provider
			err error
		)
		switch name {
		case "keycloak":
			p, err = keycloak.NewProvider(ctx, settings, k8sClient)
		case "auth0":
			p, err = auth0.New(ctx, settings, k8sClient)
		default:
			// Unreachable: ActiveProviders() only ever returns these two names.
			err = fmt.Errorf("unknown oidc provider: %q", name)
		}
		if err != nil {
			return nil, fmt.Errorf("building %s provider: %w", name, err)
		}
		providers[name] = p
	}
	return providers, nil
}
