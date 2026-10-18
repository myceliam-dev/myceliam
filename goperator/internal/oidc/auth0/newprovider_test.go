package auth0

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"myceliam/internal/certgen"
	"myceliam/internal/config"
	"myceliam/internal/operr"
)

func testSettings(t *testing.T, overrides map[string]string) *config.Settings {
	t.Helper()
	t.Setenv("MYCELIAM_AUTH0_DOMAIN", "example.us.auth0.com")
	t.Setenv("MYCELIAM_AUTH0_OPERATOR_CLIENT_ID", "operator-client-id")
	t.Setenv("MYCELIAM_CLUSTER_ID", "test-cluster")
	for k, v := range overrides {
		t.Setenv("MYCELIAM_"+k, v)
	}
	s, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return s
}

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

func TestNewUsesOpaqueSecretWhenOnlyThatExists(t *testing.T) {
	s := testSettings(t, nil)
	c := fakeClientWithObjects(t, opaqueSecret(s.SystemNamespace, AdminSecretName, "shh"))

	p, err := New(context.Background(), s, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	src, ok := p.auth.source.(*secretSource)
	if !ok {
		t.Fatalf("expected *secretSource, got %T", p.auth.source)
	}
	if src.clientID != s.Auth0OperatorClientID {
		t.Fatalf("expected clientID from Settings.Auth0OperatorClientID, got %q", src.clientID)
	}
}

func TestNewUsesKeypairSecretWhenOnlyThatExists(t *testing.T) {
	s := testSettings(t, map[string]string{"AUTH0_OPERATOR_KEYPAIR_KID": "test-kid"})
	c := fakeClientWithObjects(t, tlsKeypairSecret(t, s.SystemNamespace, AdminKeypairSecretName))

	p, err := New(context.Background(), s, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	src, ok := p.auth.source.(*signedJWTSource)
	if !ok {
		t.Fatalf("expected *signedJWTSource, got %T", p.auth.source)
	}
	if src.kid != "test-kid" {
		t.Fatalf("expected kid from Settings.Auth0OperatorKeypairKid, got %q", src.kid)
	}
}

func TestNewPrefersKeypairWhenBothSecretsExist(t *testing.T) {
	s := testSettings(t, map[string]string{"AUTH0_OPERATOR_KEYPAIR_KID": "test-kid"})
	c := fakeClientWithObjects(t,
		opaqueSecret(s.SystemNamespace, AdminSecretName, "shh"),
		tlsKeypairSecret(t, s.SystemNamespace, AdminKeypairSecretName),
	)

	p, err := New(context.Background(), s, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := p.auth.source.(*signedJWTSource); !ok {
		t.Fatalf("expected keypair to win when both secrets exist, got %T", p.auth.source)
	}
}

func TestNewFailsWhenNeitherSecretExists(t *testing.T) {
	s := testSettings(t, nil)
	c := fakeClientWithObjects(t)

	_, err := New(context.Background(), s, c)
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestNewFailsWhenKeypairPresentButKidMissing(t *testing.T) {
	s := testSettings(t, nil) // no AUTH0_OPERATOR_KEYPAIR_KID set
	c := fakeClientWithObjects(t, tlsKeypairSecret(t, s.SystemNamespace, AdminKeypairSecretName))

	_, err := New(context.Background(), s, c)
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent when kid is missing, got %v", err)
	}
}
