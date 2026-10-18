package oidc

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"myceliam/internal/config"
	"myceliam/internal/oidc/auth0"
	"myceliam/internal/oidc/keycloak"
)

func loadSettings(t *testing.T, env map[string]string) *config.Settings {
	t.Helper()
	t.Setenv("MYCELIAM_CLUSTER_ID", "test-cluster")
	for k, v := range env {
		t.Setenv("MYCELIAM_"+k, v)
	}
	s, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return s
}

// fakeK8sClient returns a client pre-populated with every admin secret every
// provider package's tests exercise here might need — simplest to seed both
// up front rather than build a different client per active-provider
// combination.
func fakeK8sClient(t *testing.T) kclient.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "myceliam-system", Name: keycloak.AdminSecretName},
			Data:       map[string][]byte{"client-secret": []byte("test-secret")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "myceliam-system", Name: auth0.AdminSecretName},
			Data:       map[string][]byte{"client-secret": []byte("test-secret")},
		},
	).Build()
}

func TestGetProvidersEmptyWhenNoneConfigured(t *testing.T) {
	s := loadSettings(t, nil)
	providers, err := GetProviders(context.Background(), s, fakeK8sClient(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(providers) != 0 {
		t.Fatalf("expected no providers, got %v", providers)
	}
}

func TestGetProvidersReturnsKeycloakWhenConfigured(t *testing.T) {
	s := loadSettings(t, map[string]string{"KEYCLOAK_URL": "https://kc.example.com"})
	providers, err := GetProviders(context.Background(), s, fakeK8sClient(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := providers["keycloak"].(*keycloak.KeycloakProvider); !ok {
		t.Fatalf("expected providers[\"keycloak\"] to be *keycloak.KeycloakProvider, got %T", providers["keycloak"])
	}
	if len(providers) != 1 {
		t.Fatalf("expected exactly 1 provider, got %v", providers)
	}
}

func TestGetProvidersReturnsAuth0WhenConfigured(t *testing.T) {
	s := loadSettings(t, map[string]string{
		"AUTH0_DOMAIN":             "example.us.auth0.com",
		"AUTH0_OPERATOR_CLIENT_ID": "operator-client-id",
	})
	providers, err := GetProviders(context.Background(), s, fakeK8sClient(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := providers["auth0"].(*auth0.Provider); !ok {
		t.Fatalf("expected providers[\"auth0\"] to be *auth0.Provider, got %T", providers["auth0"])
	}
}

func TestGetProvidersReturnsAllSimultaneouslyActive(t *testing.T) {
	s := loadSettings(t, map[string]string{
		"KEYCLOAK_URL":             "https://kc.example.com",
		"AUTH0_DOMAIN":             "example.us.auth0.com",
		"AUTH0_OPERATOR_CLIENT_ID": "operator-client-id",
		"OPERATOR_PROVIDER":        "keycloak", // required: more than one active provider
	})
	providers, err := GetProviders(context.Background(), s, fakeK8sClient(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(providers) != 2 {
		t.Fatalf("expected both providers active, got %v", providers)
	}
	if _, ok := providers["keycloak"].(*keycloak.KeycloakProvider); !ok {
		t.Fatalf("expected providers[\"keycloak\"] to be *keycloak.KeycloakProvider, got %T", providers["keycloak"])
	}
	if _, ok := providers["auth0"].(*auth0.Provider); !ok {
		t.Fatalf("expected providers[\"auth0\"] to be *auth0.Provider, got %T", providers["auth0"])
	}
}
