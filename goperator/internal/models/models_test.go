package models

import (
	"testing"

	"myceliam/internal/config"
	"myceliam/internal/operr"
)

func settings(t *testing.T) *config.Settings {
	t.Helper()
	t.Setenv("MYCELIAM_KEYCLOAK_URL", "https://kc.example.com")
	t.Setenv("MYCELIAM_CLUSTER_ID", "test-cluster")
	s, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return s
}

func TestParseSecretClientSpec(t *testing.T) {
	spec, err := ParseClientSpec("demo", "my-app", map[string]string{ClientTypeLabel: "secret"}, settings(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Realm != "test-cluster-demo" || spec.ClientName != "my-app" || spec.ClientType != ClientTypeSecret {
		t.Fatalf("unexpected spec: %+v", spec)
	}
	if spec.CredentialsSecretName != "my-app-oidc-credentials" {
		t.Fatalf("unexpected CredentialsSecretName: %v", spec.CredentialsSecretName)
	}
}

func TestParseSignedjwtClientSpec(t *testing.T) {
	spec, err := ParseClientSpec("demo", "my-app", map[string]string{ClientTypeLabel: "signedjwt"}, settings(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.ClientType != ClientTypeSignedJWT {
		t.Fatalf("unexpected ClientType: %v", spec.ClientType)
	}
}

func TestMissingClienttypeRaisesPermanentError(t *testing.T) {
	_, err := ParseClientSpec("demo", "my-app", map[string]string{}, settings(t))
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestInvalidClienttypeRaisesPermanentError(t *testing.T) {
	_, err := ParseClientSpec("demo", "my-app", map[string]string{ClientTypeLabel: "bogus"}, settings(t))
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}
