// Package okta ports pythonoperator/src/myceliam/oidc_providers/okta/client.py:
// a placeholder oidc.Provider implementation. Scaffolding only — every
// operation returns an error until Okta support is actually built.
package okta

import (
	"context"
	"fmt"

	"myceliam/internal/config"
	"myceliam/internal/models"
)

var errNotImplemented = fmt.Errorf("Okta support is not implemented yet")

type Provider struct {
	settings *config.Settings
}

func New(settings *config.Settings) *Provider {
	return &Provider{settings: settings}
}

func (p *Provider) EnsureTenant(ctx context.Context, tenantID string) error {
	return errNotImplemented
}

func (p *Provider) DeleteTenant(ctx context.Context, tenantID string) error {
	return errNotImplemented
}

func (p *Provider) EnsureSecretClient(ctx context.Context, spec *models.ClientSpec) (string, string, error) {
	return "", "", errNotImplemented
}

func (p *Provider) EnsureSignedjwtClient(ctx context.Context, spec *models.ClientSpec, jwksString string) (string, error) {
	return "", errNotImplemented
}

func (p *Provider) DeleteClient(ctx context.Context, tenantID, clientName string) error {
	return errNotImplemented
}

func (p *Provider) IssuerURL(tenantID string) (string, error) {
	return "", errNotImplemented
}

func (p *Provider) EnsureAccessScope(ctx context.Context, tenantID, clientName, scopeName, audience string) error {
	return errNotImplemented
}

func (p *Provider) DeleteAccessScope(ctx context.Context, tenantID, scopeName string) error {
	return errNotImplemented
}

func (p *Provider) GetOperatorToken(ctx context.Context) (string, error) {
	return "", errNotImplemented
}
