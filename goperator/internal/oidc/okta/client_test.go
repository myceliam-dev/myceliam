package okta

import (
	"context"
	"testing"

	"myceliam/internal/config"
	"myceliam/internal/models"
)

func testProvider(t *testing.T) *Provider {
	t.Helper()
	t.Setenv("MYCELIAM_KEYCLOAK_URL", "https://kc.example.com")
	t.Setenv("MYCELIAM_CLUSTER_ID", "test-cluster")
	s, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return New(s)
}

func testSpec() *models.ClientSpec {
	return &models.ClientSpec{
		Realm: "demo", ClientName: "my-app", ClientType: models.ClientTypeSecret, CredentialsSecretName: "x",
	}
}

func TestEveryOperationReturnsNotImplemented(t *testing.T) {
	p := testProvider(t)
	ctx := context.Background()

	if err := p.EnsureTenant(ctx, "demo"); err == nil {
		t.Fatal("expected error from EnsureTenant")
	}
	if err := p.DeleteTenant(ctx, "demo"); err == nil {
		t.Fatal("expected error from DeleteTenant")
	}
	if _, _, err := p.EnsureSecretClient(ctx, testSpec()); err == nil {
		t.Fatal("expected error from EnsureSecretClient")
	}
	if _, err := p.EnsureSignedjwtClient(ctx, testSpec(), `{"keys": []}`); err == nil {
		t.Fatal("expected error from EnsureSignedjwtClient")
	}
	if err := p.DeleteClient(ctx, "demo", "my-app"); err == nil {
		t.Fatal("expected error from DeleteClient")
	}
	if _, err := p.IssuerURL("demo"); err == nil {
		t.Fatal("expected error from IssuerURL")
	}
	if err := p.EnsureAccessScope(ctx, "demo", "my-app", "scope-1", "sts.amazonaws.com"); err == nil {
		t.Fatal("expected error from EnsureAccessScope")
	}
	if err := p.DeleteAccessScope(ctx, "demo", "scope-1"); err == nil {
		t.Fatal("expected error from DeleteAccessScope")
	}
	if _, err := p.GetOperatorToken(ctx); err == nil {
		t.Fatal("expected error from GetOperatorToken")
	}
}
