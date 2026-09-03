package keycloak

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"myceliam/internal/certgen"
	"myceliam/internal/operr"
)

func fakeClientWithObjects(t *testing.T, objs ...kclient.Object) kclient.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func opaqueSecret(ns, name, clientSecret string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Data:       map[string][]byte{"client-secret": []byte(clientSecret)},
	}
}

func tlsKeypairSecret(t *testing.T, ns, name string) *corev1.Secret {
	t.Helper()
	certPEM, keyPEM, err := certgen.GenerateSelfSignedKeypair("myceliam-operator", 2048, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}
}

func TestNewProviderUsesOpaqueSecretWhenOnlyThatExists(t *testing.T) {
	s := testSettings(t)
	c := fakeClientWithObjects(t, opaqueSecret(s.SystemNamespace, AdminSecretName, "shh"))

	p, err := NewProvider(context.Background(), s, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	src, ok := p.auth.(*adminAuth).source.(*gocloakSecretSource)
	if !ok {
		t.Fatalf("expected gocloakSecretSource, got %T", p.auth.(*adminAuth).source)
	}
	if src.clientID != s.KeycloakClientID {
		t.Fatalf("expected clientID from Settings.KeycloakClientID, got %q", src.clientID)
	}
}

func TestNewProviderUsesKeypairSecretWhenOnlyThatExists(t *testing.T) {
	s := testSettings(t)
	c := fakeClientWithObjects(t, tlsKeypairSecret(t, s.SystemNamespace, AdminKeypairSecretName))

	p, err := NewProvider(context.Background(), s, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	src, ok := p.auth.(*adminAuth).source.(*signedJWTSource)
	if !ok {
		t.Fatalf("expected *signedJWTSource, got %T", p.auth.(*adminAuth).source)
	}
	if src.clientID != s.KeycloakClientID {
		t.Fatalf("expected clientID from Settings.KeycloakClientID, got %q", src.clientID)
	}
}

func TestNewProviderPrefersKeypairWhenBothSecretsExist(t *testing.T) {
	s := testSettings(t)
	c := fakeClientWithObjects(t,
		opaqueSecret(s.SystemNamespace, AdminSecretName, "shh"),
		tlsKeypairSecret(t, s.SystemNamespace, AdminKeypairSecretName),
	)

	p, err := NewProvider(context.Background(), s, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := p.auth.(*adminAuth).source.(*signedJWTSource); !ok {
		t.Fatalf("expected keypair to win when both secrets exist, got %T", p.auth.(*adminAuth).source)
	}
}

func TestNewProviderFailsWhenNeitherSecretExists(t *testing.T) {
	s := testSettings(t)
	c := fakeClientWithObjects(t)

	_, err := NewProvider(context.Background(), s, c)
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestNewProviderFailsWhenKeypairSecretMissingPrivateKey(t *testing.T) {
	s := testSettings(t)
	certPEM, _, err := certgen.GenerateSelfSignedKeypair("myceliam-operator", 2048, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	incomplete := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: s.SystemNamespace, Name: AdminKeypairSecretName},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: certPEM},
	}
	c := fakeClientWithObjects(t, incomplete)

	_, err = NewProvider(context.Background(), s, c)
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}
