package config

import (
	"strings"
	"testing"
)

func TestKeycloakURLRequiredForKeycloakProvider(t *testing.T) {
	s := &Settings{OidcProvider: "keycloak"}
	err := s.validateProviderConfig()
	if err == nil || !strings.Contains(err.Error(), "MYCELIAM_KEYCLOAK_URL") {
		t.Fatalf("expected MYCELIAM_KEYCLOAK_URL error, got %v", err)
	}
}

func TestKeycloakProviderIsTheDefaultAndStillRequiresURL(t *testing.T) {
	s := &Settings{OidcProvider: "keycloak"} // zero-value KeycloakURL, same as the default
	err := s.validateProviderConfig()
	if err == nil || !strings.Contains(err.Error(), "MYCELIAM_KEYCLOAK_URL") {
		t.Fatalf("expected MYCELIAM_KEYCLOAK_URL error, got %v", err)
	}
}

func TestKeycloakURLAcceptedWhenProvided(t *testing.T) {
	s := &Settings{OidcProvider: "keycloak", KeycloakURL: "https://kc.example.com"}
	if err := s.validateProviderConfig(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.KeycloakURL != "https://kc.example.com" {
		t.Fatalf("unexpected KeycloakURL: %v", s.KeycloakURL)
	}
}

func TestNoneProviderDoesNotRequireKeycloakURL(t *testing.T) {
	s := &Settings{OidcProvider: "none"}
	if err := s.validateProviderConfig(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOktaProviderDoesNotRequireKeycloakURL(t *testing.T) {
	s := &Settings{OidcProvider: "okta"}
	if err := s.validateProviderConfig(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnknownProviderRejectedAtConstruction(t *testing.T) {
	s := &Settings{OidcProvider: "not-a-real-provider"}
	err := s.validateProviderConfig()
	if err == nil || !strings.Contains(err.Error(), "unknown MYCELIAM_OIDC_PROVIDER") {
		t.Fatalf("expected unknown-provider error, got %v", err)
	}
}

func TestLoadDefaultsAndEnvOverrides(t *testing.T) {
	t.Setenv("MYCELIAM_KEYCLOAK_URL", "https://kc.example.com")
	t.Setenv("MYCELIAM_CLUSTER_ID", "test-cluster")
	t.Setenv("MYCELIAM_SIGNEDJWT_KEY_SIZE", "4096")
	t.Setenv("MYCELIAM_RECONCILE_INTERVAL_SECONDS", "60.5")
	t.Setenv("MYCELIAM_KEYCLOAK_VERIFY_SSL", "false")

	s, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.OidcProvider != "keycloak" {
		t.Fatalf("expected default oidc_provider=keycloak, got %v", s.OidcProvider)
	}
	if s.SignedjwtKeySize != 4096 {
		t.Fatalf("expected SignedjwtKeySize=4096, got %v", s.SignedjwtKeySize)
	}
	if s.ReconcileIntervalSeconds != 60.5 {
		t.Fatalf("expected ReconcileIntervalSeconds=60.5, got %v", s.ReconcileIntervalSeconds)
	}
	if s.KeycloakVerifySSL != false {
		t.Fatalf("expected KeycloakVerifySSL=false, got %v", s.KeycloakVerifySSL)
	}
	if s.CredentialsSecretSuffix != "-oidc-credentials" {
		t.Fatalf("expected default CredentialsSecretSuffix, got %v", s.CredentialsSecretSuffix)
	}
}

func TestLoadFailsFastOnMissingKeycloakURL(t *testing.T) {
	t.Setenv("MYCELIAM_CLUSTER_ID", "test-cluster")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MYCELIAM_KEYCLOAK_URL") {
		t.Fatalf("expected MYCELIAM_KEYCLOAK_URL error, got %v", err)
	}
}

func TestLoadFailsFastOnMissingClusterID(t *testing.T) {
	t.Setenv("MYCELIAM_KEYCLOAK_URL", "https://kc.example.com")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MYCELIAM_CLUSTER_ID") {
		t.Fatalf("expected MYCELIAM_CLUSTER_ID error, got %v", err)
	}
}
