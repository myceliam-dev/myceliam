package k8shelpers

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	myceliamv1 "myceliam/api/v1"
	"myceliam/internal/operr"
)

func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := myceliamv1.AddToScheme(scheme); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func TestReadAccessProfileFound(t *testing.T) {
	profile := &myceliamv1.AwsAccessProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ap1"},
		Accounts:   map[string][]string{"111111111111": {"role-a"}},
	}
	c := newFakeClient(t, profile)

	var got myceliamv1.AwsAccessProfile
	found, err := ReadAccessProfile(context.Background(), c, "default", "ap1", &got)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || len(got.Accounts) != 1 || len(got.Accounts["111111111111"]) != 1 || got.Accounts["111111111111"][0] != "role-a" {
		t.Fatalf("unexpected result: found=%v got=%+v", found, got)
	}
}

func TestReadAccessProfileNotFound(t *testing.T) {
	c := newFakeClient(t)
	var got myceliamv1.AwsAccessProfile
	found, err := ReadAccessProfile(context.Background(), c, "default", "missing", &got)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatalf("expected not found")
	}
}

func TestListServiceAccountsByLabel(t *testing.T) {
	matching := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "matches", Labels: map[string]string{"k": "v"}},
	}
	nonMatching := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "no-match", Labels: map[string]string{"k": "other"}},
	}
	c := newFakeClient(t, matching, nonMatching)

	selector, err := labels.Parse("k=v")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	items, err := ListServiceAccountsByLabel(context.Background(), c, "ns1", selector)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 || items[0].Name != "matches" {
		t.Fatalf("unexpected result: %+v", items)
	}
}

func TestReadSecretKeyIfPresentMissingSecret(t *testing.T) {
	c := newFakeClient(t)
	_, found, err := ReadSecretKeyIfPresent(context.Background(), c, "default", "missing", "tls.crt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatalf("expected not found")
	}
}

func TestReadSecretKeyIfPresentMissingKeyIsPermanent(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "sec"},
		Data:       map[string][]byte{"other-key": []byte("x")},
	}
	c := newFakeClient(t, secret)

	_, _, err := ReadSecretKeyIfPresent(context.Background(), c, "default", "sec", "tls.crt")
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestReadSecretKeyIfPresentReturnsValue(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "sec"},
		Data:       map[string][]byte{"tls.crt": []byte("cert-bytes")},
	}
	c := newFakeClient(t, secret)

	value, found, err := ReadSecretKeyIfPresent(context.Background(), c, "default", "sec", "tls.crt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || string(value) != "cert-bytes" {
		t.Fatalf("unexpected result: found=%v value=%q", found, value)
	}
}

func TestCreateTLSSecretIfAbsentCreates(t *testing.T) {
	c := newFakeClient(t)
	owner := metav1.OwnerReference{APIVersion: "v1", Kind: "ServiceAccount", Name: "my-app", UID: "uid-1"}

	err := CreateTLSSecretIfAbsent(context.Background(), c, "default", "my-app-oidc-credentials", []byte("cert"), []byte("key"), owner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var secret corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "my-app-oidc-credentials"}, &secret); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Type != corev1.SecretTypeTLS || string(secret.Data["tls.crt"]) != "cert" {
		t.Fatalf("unexpected secret: %+v", secret)
	}
}

func TestCreateTLSSecretIfAbsentNoopsOnExisting(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-app-oidc-credentials"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": []byte("user-provided")},
	}
	c := newFakeClient(t, existing)
	owner := metav1.OwnerReference{APIVersion: "v1", Kind: "ServiceAccount", Name: "my-app", UID: "uid-1"}

	err := CreateTLSSecretIfAbsent(context.Background(), c, "default", "my-app-oidc-credentials", []byte("generated"), []byte("key"), owner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var secret corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "my-app-oidc-credentials"}, &secret); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(secret.Data["tls.crt"]) != "user-provided" {
		t.Fatalf("expected pre-existing secret left untouched, got %q", secret.Data["tls.crt"])
	}
}

func TestWriteCredentialsSecretCreatesWhenAbsent(t *testing.T) {
	c := newFakeClient(t)
	owner := metav1.OwnerReference{APIVersion: "v1", Kind: "ServiceAccount", Name: "my-app", UID: "uid-1"}

	err := WriteCredentialsSecret(context.Background(), c, "default", "my-app-oidc-credentials",
		map[string]string{"client_id": "my-app", "client_secret": "s3cr3t"}, owner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var secret corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "my-app-oidc-credentials"}, &secret); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(secret.Data["client_secret"]) != "s3cr3t" {
		t.Fatalf("unexpected secret: %+v", secret)
	}
}

func TestWriteCredentialsSecretUpdatesWhenPresent(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-app-oidc-credentials"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"client_secret": []byte("old-secret")},
	}
	c := newFakeClient(t, existing)
	owner := metav1.OwnerReference{APIVersion: "v1", Kind: "ServiceAccount", Name: "my-app", UID: "uid-1"}

	err := WriteCredentialsSecret(context.Background(), c, "default", "my-app-oidc-credentials",
		map[string]string{"client_secret": "new-secret"}, owner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var secret corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "my-app-oidc-credentials"}, &secret); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(secret.Data["client_secret"]) != "new-secret" {
		t.Fatalf("expected updated secret, got %q", secret.Data["client_secret"])
	}
}
