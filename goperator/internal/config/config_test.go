package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestActiveProvidersEmptyByDefault(t *testing.T) {
	s := &Settings{}
	if got := s.ActiveProviders(); len(got) != 0 {
		t.Fatalf("expected no active providers, got %v", got)
	}
}

func TestActiveProvidersDetectsEachIndependently(t *testing.T) {
	s := &Settings{
		KeycloakURL:           "https://kc.example.com",
		Auth0Domain:           "example.us.auth0.com",
		Auth0OperatorClientID: "client-id",
	}
	got := s.ActiveProviders()
	want := []string{"keycloak", "auth0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestActiveProvidersAuth0RequiresBothDomainAndClientID(t *testing.T) {
	s := &Settings{Auth0Domain: "example.us.auth0.com"} // no Auth0OperatorClientID
	if got := s.ActiveProviders(); len(got) != 0 {
		t.Fatalf("expected auth0 not active without a client ID, got %v", got)
	}
}

func TestValidateProviderConfigRequiresAuth0ClientIDWhenDomainSet(t *testing.T) {
	s := &Settings{Auth0Domain: "example.us.auth0.com"}
	err := s.validateProviderConfig()
	if err == nil || !strings.Contains(err.Error(), "MYCELIAM_AUTH0_OPERATOR_CLIENT_ID") {
		t.Fatalf("expected MYCELIAM_AUTH0_OPERATOR_CLIENT_ID error, got %v", err)
	}
}

func TestValidateProviderConfigNoProvidersDefaultsOperatorToSpiffe(t *testing.T) {
	s := &Settings{}
	if err := s.validateProviderConfig(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.OperatorProvider != "spiffe" {
		t.Fatalf("expected OperatorProvider defaulted to spiffe, got %q", s.OperatorProvider)
	}
}

func TestValidateProviderConfigSingleActiveProviderDefaultsOperatorToIt(t *testing.T) {
	s := &Settings{KeycloakURL: "https://kc.example.com"}
	if err := s.validateProviderConfig(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.OperatorProvider != "keycloak" {
		t.Fatalf("expected OperatorProvider defaulted to keycloak, got %q", s.OperatorProvider)
	}
}

func TestValidateProviderConfigMultipleActiveRequiresExplicitOperatorProvider(t *testing.T) {
	s := &Settings{
		KeycloakURL:           "https://kc.example.com",
		Auth0Domain:           "example.us.auth0.com",
		Auth0OperatorClientID: "client-id",
	}
	err := s.validateProviderConfig()
	if err == nil || !strings.Contains(err.Error(), "MYCELIAM_OPERATOR_PROVIDER is required") {
		t.Fatalf("expected MYCELIAM_OPERATOR_PROVIDER-required error, got %v", err)
	}
}

func TestValidateProviderConfigExplicitOperatorProviderMustBeActiveOrSpiffe(t *testing.T) {
	s := &Settings{
		KeycloakURL:      "https://kc.example.com",
		OperatorProvider: "auth0", // not active — no Auth0Domain set
	}
	err := s.validateProviderConfig()
	if err == nil || !strings.Contains(err.Error(), `MYCELIAM_OPERATOR_PROVIDER="auth0"`) {
		t.Fatalf("expected invalid-operator-provider error, got %v", err)
	}
}

func TestValidateProviderConfigExplicitOperatorProviderSpiffeAlwaysAllowed(t *testing.T) {
	s := &Settings{
		KeycloakURL:           "https://kc.example.com",
		Auth0Domain:           "example.us.auth0.com",
		Auth0OperatorClientID: "client-id",
		OperatorProvider:      "spiffe",
	}
	if err := s.validateProviderConfig(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.OperatorProvider != "spiffe" {
		t.Fatalf("expected OperatorProvider to stay spiffe, got %q", s.OperatorProvider)
	}
}

func TestValidateProviderConfigExplicitOperatorProviderAmongActiveAccepted(t *testing.T) {
	s := &Settings{
		KeycloakURL:           "https://kc.example.com",
		Auth0Domain:           "example.us.auth0.com",
		Auth0OperatorClientID: "client-id",
		OperatorProvider:      "auth0",
	}
	if err := s.validateProviderConfig(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.OperatorProvider != "auth0" {
		t.Fatalf("expected OperatorProvider to stay auth0, got %q", s.OperatorProvider)
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
	if got := s.ActiveProviders(); len(got) != 1 || got[0] != "keycloak" {
		t.Fatalf("expected only keycloak active, got %v", got)
	}
	if s.OperatorProvider != "keycloak" {
		t.Fatalf("expected OperatorProvider defaulted to keycloak, got %v", s.OperatorProvider)
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
}

func TestLoadWithNoProvidersDefaultsOperatorToSpiffe(t *testing.T) {
	t.Setenv("MYCELIAM_CLUSTER_ID", "test-cluster")
	s, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := s.ActiveProviders(); len(got) != 0 {
		t.Fatalf("expected no active providers, got %v", got)
	}
	if s.OperatorProvider != "spiffe" {
		t.Fatalf("expected OperatorProvider defaulted to spiffe, got %v", s.OperatorProvider)
	}
}

func TestLoadFailsFastOnMissingClusterID(t *testing.T) {
	t.Setenv("MYCELIAM_KEYCLOAK_URL", "https://kc.example.com")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MYCELIAM_CLUSTER_ID") {
		t.Fatalf("expected MYCELIAM_CLUSTER_ID error, got %v", err)
	}
}
