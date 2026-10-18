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
	spec, err := ParseClientSpec("demo", "my-app", map[string]string{ClientTypeLabel: "secret"}, "keycloak", settings(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Realm != "test-cluster-demo" || spec.ClientName != "my-app" || spec.ClientType != ClientTypeSecret {
		t.Fatalf("unexpected spec: %+v", spec)
	}
	if spec.CredentialsSecretName != "my-app-secret-keycloak-credentials" {
		t.Fatalf("unexpected CredentialsSecretName: %v", spec.CredentialsSecretName)
	}
	if spec.MetadataSecretName != "my-app-secret-keycloak-metadata" {
		t.Fatalf("unexpected MetadataSecretName: %v", spec.MetadataSecretName)
	}
}

func TestParseSignedjwtClientSpec(t *testing.T) {
	spec, err := ParseClientSpec("demo", "my-app", map[string]string{ClientTypeLabel: "signedjwt"}, "keycloak", settings(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.ClientType != ClientTypeSignedJWT {
		t.Fatalf("unexpected ClientType: %v", spec.ClientType)
	}
	if spec.CredentialsSecretName != "my-app-jwt-keycloak-credentials" {
		t.Fatalf("unexpected CredentialsSecretName: %v", spec.CredentialsSecretName)
	}
	if spec.MetadataSecretName != "my-app-jwt-keycloak-metadata" {
		t.Fatalf("unexpected MetadataSecretName: %v", spec.MetadataSecretName)
	}
}

func TestCredentialsSecretNamesVaryByProvider(t *testing.T) {
	credKeycloak, metaKeycloak := credentialsSecretNames("my-app", ClientTypeSecret, "keycloak")
	if credKeycloak != "my-app-secret-keycloak-credentials" || metaKeycloak != "my-app-secret-keycloak-metadata" {
		t.Fatalf("unexpected keycloak names: %q, %q", credKeycloak, metaKeycloak)
	}
	credAuth0, metaAuth0 := credentialsSecretNames("my-app", ClientTypeSignedJWT, "auth0")
	if credAuth0 != "my-app-jwt-auth0-credentials" || metaAuth0 != "my-app-jwt-auth0-metadata" {
		t.Fatalf("unexpected auth0 names: %q, %q", credAuth0, metaAuth0)
	}
}

func TestMissingClienttypeRaisesPermanentError(t *testing.T) {
	_, err := ParseClientSpec("demo", "my-app", map[string]string{}, "keycloak", settings(t))
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestInvalidClienttypeRaisesPermanentError(t *testing.T) {
	_, err := ParseClientSpec("demo", "my-app", map[string]string{ClientTypeLabel: "bogus"}, "keycloak", settings(t))
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}
