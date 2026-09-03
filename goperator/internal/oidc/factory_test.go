package oidc

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"myceliam/internal/config"
	"myceliam/internal/oidc/keycloak"
	"myceliam/internal/oidc/okta"
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

// fakeK8sClient returns a client pre-populated with myceliam-keycloak-secret
// in myceliam-system, satisfying keycloak.NewProvider's secret
// auto-detection for tests exercising the "keycloak" provider path.
func fakeK8sClient(t *testing.T) kclient.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "myceliam-system", Name: keycloak.AdminSecretName},
		Data:       map[string][]byte{"client-secret": []byte("test-secret")},
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
}

func TestGetProviderDefaultsToKeycloak(t *testing.T) {
	s := loadSettings(t, map[string]string{"KEYCLOAK_URL": "https://kc.example.com"})
	p, err := GetProvider(context.Background(), s, fakeK8sClient(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := p.(*keycloak.KeycloakProvider); !ok {
		t.Fatalf("expected *keycloak.KeycloakProvider, got %T", p)
	}
}

func TestGetProviderReturnsOkta(t *testing.T) {
	s := loadSettings(t, map[string]string{"KEYCLOAK_URL": "https://kc.example.com", "OIDC_PROVIDER": "okta"})
	p, err := GetProvider(context.Background(), s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := p.(*okta.Provider); !ok {
		t.Fatalf("expected *okta.Provider, got %T", p)
	}
}

func TestGetProviderRejectsUnknown(t *testing.T) {
	// auth0 is a *known* MYCELIAM_OIDC_PROVIDER value (config.Load accepts it)
	// but has no factory case yet — mirrors get_provider raising ValueError
	// for a recognized-but-unimplemented provider name.
	s := loadSettings(t, map[string]string{"KEYCLOAK_URL": "https://kc.example.com", "OIDC_PROVIDER": "auth0"})
	_, err := GetProvider(context.Background(), s, nil)
	if err == nil || !strings.Contains(err.Error(), "auth0") {
		t.Fatalf("expected error mentioning auth0, got %v", err)
	}
}

func TestGetProviderReturnsNilForNoneProvider(t *testing.T) {
	s := loadSettings(t, map[string]string{"OIDC_PROVIDER": "none"})
	p, err := GetProvider(context.Background(), s, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Fatalf("expected nil provider, got %v", p)
	}
}
