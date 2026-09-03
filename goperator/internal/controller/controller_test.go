package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	myceliamv1 "myceliam/api/v1"
	"myceliam/internal/certgen"
	"myceliam/internal/cloudmodels"
	"myceliam/internal/config"
	"myceliam/internal/models"
)

func newTestClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := myceliamv1.AddToScheme(scheme); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&myceliamv1.AwsAccessProfile{}, &myceliamv1.GcpAccessProfile{}).
		Build()
}

func testSettings(t *testing.T) *config.Settings {
	t.Helper()
	t.Setenv("MYCELIAM_KEYCLOAK_URL", "https://kc.example.com")
	t.Setenv("MYCELIAM_CLUSTER_ID", "test-cluster")
	s, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return s
}

// fakeOIDCProvider is a minimal oidc.Provider test double recording calls,
// analogous to the fakeAdmin/fakeProvider doubles used elsewhere in this port.
type fakeOIDCProvider struct {
	secretClientID     string
	secretClientSecret string
	signedjwtClientID  string
	issuer             string

	ensureTenantCalls []string
	deleteClientCalls []string
	deleteTenantCalls []string
	issuerURLCalls    []string
	ensureScopeCalls  int
	deleteScopeCalls  int
}

func (f *fakeOIDCProvider) EnsureTenant(ctx context.Context, tenantID string) error {
	f.ensureTenantCalls = append(f.ensureTenantCalls, tenantID)
	return nil
}
func (f *fakeOIDCProvider) DeleteTenant(ctx context.Context, tenantID string) error {
	f.deleteTenantCalls = append(f.deleteTenantCalls, tenantID)
	return nil
}
func (f *fakeOIDCProvider) EnsureSecretClient(ctx context.Context, spec *models.ClientSpec) (string, string, error) {
	return f.secretClientID, f.secretClientSecret, nil
}
func (f *fakeOIDCProvider) EnsureSignedjwtClient(ctx context.Context, spec *models.ClientSpec, jwksString string) (string, error) {
	return f.signedjwtClientID, nil
}
func (f *fakeOIDCProvider) DeleteClient(ctx context.Context, tenantID, clientName string) error {
	f.deleteClientCalls = append(f.deleteClientCalls, tenantID+"/"+clientName)
	return nil
}
func (f *fakeOIDCProvider) IssuerURL(tenantID string) (string, error) {
	f.issuerURLCalls = append(f.issuerURLCalls, tenantID)
	return f.issuer, nil
}
func (f *fakeOIDCProvider) EnsureAccessScope(ctx context.Context, tenantID, clientName, scopeName, audience string) error {
	f.ensureScopeCalls++
	return nil
}
func (f *fakeOIDCProvider) DeleteAccessScope(ctx context.Context, tenantID, scopeName string) error {
	f.deleteScopeCalls++
	return nil
}
func (f *fakeOIDCProvider) GetOperatorToken(ctx context.Context) (string, error) { return "", nil }

func reconcileRequest(namespace, name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}}
}

func TestServiceAccountReconciler_AddsFinalizerFirst(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "my-app",
			Labels: map[string]string{models.AutoidpLabel: "true", models.ClientTypeLabel: "secret"},
		},
	}
	c := newTestClient(t, sa)
	fp := &fakeOIDCProvider{secretClientID: "my-app", secretClientSecret: "s3cr3t", issuer: "https://kc.example.com/realms/demo"}
	r := &ServiceAccountReconciler{Deps: &Deps{Client: c, Settings: testSettings(t), OIDC: fp}}

	if _, err := r.Reconcile(context.Background(), reconcileRequest("demo", "my-app")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got corev1.ServiceAccount
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "demo", Name: "my-app"}, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&got, finalizerName) {
		t.Fatalf("expected finalizer to be added")
	}
	if len(fp.ensureTenantCalls) != 0 {
		t.Fatalf("expected no reconcile work on the finalizer-add pass, got %v", fp.ensureTenantCalls)
	}
}

func TestServiceAccountReconciler_ReconcilesSecretClientAndWritesState(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "my-app",
			Labels:     map[string]string{models.AutoidpLabel: "true", models.ClientTypeLabel: "secret"},
			Finalizers: []string{finalizerName},
		},
	}
	c := newTestClient(t, sa)
	fp := &fakeOIDCProvider{secretClientID: "my-app", secretClientSecret: "s3cr3t", issuer: "https://kc.example.com/realms/demo"}
	r := &ServiceAccountReconciler{Deps: &Deps{Client: c, Settings: testSettings(t), OIDC: fp}}

	result, err := r.Reconcile(context.Background(), reconcileRequest("demo", "my-app"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected periodic RequeueAfter, got %v", result)
	}
	if len(fp.ensureTenantCalls) != 1 || fp.ensureTenantCalls[0] != "test-cluster-demo" {
		t.Fatalf("expected EnsureTenant('test-cluster-demo'), got %v", fp.ensureTenantCalls)
	}

	var secret corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "demo", Name: "my-app-oidc-credentials"}, &secret); err != nil {
		t.Fatalf("expected credentials secret to be written: %v", err)
	}
	if string(secret.Data["client_secret"]) != "s3cr3t" {
		t.Fatalf("unexpected secret data: %+v", secret.Data)
	}

	var sa2 corev1.ServiceAccount
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "demo", Name: "my-app"}, &sa2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := sa2.Annotations[lastReconciledAnnotation]; !ok {
		t.Fatalf("expected last-reconciled-state annotation to be written")
	}
}

func TestServiceAccountReconciler_SpiffeReconcileRequiresIssuerAnnotation(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "my-app",
			Labels:     map[string]string{models.AutoidpLabel: "true", models.ClientTypeLabel: "spiffe"},
			Finalizers: []string{finalizerName},
		},
	}
	c := newTestClient(t, sa)
	r := &ServiceAccountReconciler{Deps: &Deps{Client: c, Settings: testSettings(t), OIDC: nil}}

	// Missing SpiffeJWTIssuerAnnotation is a *operr.Permanent — classify
	// turns that into a nil-error, periodically-requeued result rather than
	// a Go error (see result.go's doc comment).
	result, err := r.Reconcile(context.Background(), reconcileRequest("demo", "my-app"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected periodic requeue even after a permanent misconfiguration, got %v", result)
	}
}

func TestServiceAccountReconciler_CleanupOnDelete(t *testing.T) {
	now := metav1.Now()
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "my-app",
			Labels:            map[string]string{models.AutoidpLabel: "true", models.ClientTypeLabel: "secret"},
			Finalizers:        []string{finalizerName},
			DeletionTimestamp: &now,
		},
	}
	c := newTestClient(t, sa)
	fp := &fakeOIDCProvider{}
	r := &ServiceAccountReconciler{Deps: &Deps{Client: c, Settings: testSettings(t), OIDC: fp}}

	if _, err := r.Reconcile(context.Background(), reconcileRequest("demo", "my-app")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fp.deleteClientCalls) != 1 || fp.deleteClientCalls[0] != "test-cluster-demo/my-app" {
		t.Fatalf("expected DeleteClient('test-cluster-demo','my-app'), got %v", fp.deleteClientCalls)
	}

	var got corev1.ServiceAccount
	err := c.Get(context.Background(), client.ObjectKey{Namespace: "demo", Name: "my-app"}, &got)
	if err == nil && controllerutil.ContainsFinalizer(&got, finalizerName) {
		t.Fatalf("expected finalizer to be removed")
	}
}

func TestAwsAccessProfileReconciler_FinalizerAndCleanup(t *testing.T) {
	profile := &myceliamv1.AwsAccessProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "ap1"},
		// Empty on purpose: cleanup's per-account DeleteIdp loop must not run
		// (avoiding a real AWS call from this test) while still exercising
		// finalizer add/remove and Deps.OIDC-nil short-circuit wiring.
		Accounts: map[string][]string{},
	}
	c := newTestClient(t, profile)
	r := &AwsAccessProfileReconciler{Deps: &Deps{Client: c, Settings: testSettings(t), OIDC: nil}}

	if _, err := r.Reconcile(context.Background(), reconcileRequest("demo", "ap1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got myceliamv1.AwsAccessProfile
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "demo", Name: "ap1"}, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&got, finalizerName) {
		t.Fatalf("expected finalizer added")
	}

	now := metav1.Now()
	got.DeletionTimestamp = &now
	if _, err := r.Reconcile(context.Background(), reconcileRequest("demo", "ap1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRefreshServiceAccountsForProfile_ExcludesSpiffeSAs is a regression test:
// refreshServiceAccountsForProfile must not call reconcileCloud (the
// Keycloak-backed path) for a clienttype=spiffe SA — that SA was never
// registered as a Keycloak client, so EnsureAccessScope's client lookup would
// fail every time this profile is touched, forever (see reconcile.go's doc
// comment on refreshServiceAccountsForProfile for the full explanation).
func TestRefreshServiceAccountsForProfile_ExcludesSpiffeSAs(t *testing.T) {
	profile := &myceliamv1.AwsAccessProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo-ns1", Name: "awsap-demo-ns1"},
		// Empty on purpose: reconcileCloud's per-account credential-fetch loop
		// must not run (it would hit the real operatoridentity token-exchange
		// path, which isn't what this test is exercising) while still
		// covering the EnsureAccessScope call this test asserts on. With no
		// accounts listed, reconcileCloud's aws loop simply iterates zero
		// times and returns nil — not an error.
		Accounts: map[string][]string{},
	}
	secretSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo-ns1", Name: "gosa-secret",
			Labels: map[string]string{
				models.AutoidpLabel:         "true",
				models.ClientTypeLabel:      "secret",
				cloudmodels.AwsProfileLabel: "awsap-demo-ns1",
			},
		},
	}
	spiffeSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo-ns1", Name: "demo-ns1-spiffe",
			Labels: map[string]string{
				models.AutoidpLabel:         "true",
				models.ClientTypeLabel:      "spiffe",
				cloudmodels.AwsProfileLabel: "awsap-demo-ns1",
			},
			Annotations: map[string]string{models.SpiffeJWTIssuerAnnotation: "https://spire1-oidc.example.com"},
		},
	}
	c := newTestClient(t, profile, secretSA, spiffeSA)
	fp := &fakeOIDCProvider{issuer: "https://kc.example.com/realms/demo-ns1"}
	deps := &Deps{Client: c, Settings: testSettings(t), OIDC: fp}

	err := refreshServiceAccountsForProfile(context.Background(), deps, "demo-ns1", cloudmodels.AwsProfileLabel, "awsap-demo-ns1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the secret SA's scope should have been ensured — the spiffe SA
	// must never reach EnsureAccessScope (it would try to find a Keycloak
	// client that doesn't exist).
	if fp.ensureScopeCalls != 1 {
		t.Fatalf("expected exactly 1 EnsureAccessScope call (secret SA only), got %d", fp.ensureScopeCalls)
	}
	// Regression coverage: reconcileCloud's own IssuerURL lookup must use the
	// cluster-prefixed realm (models.RealmForNamespace), not the raw
	// namespace — these independently compute "the realm name" and drifted
	// out of sync once before (namespace alone produced the pre-ClusterID
	// realm, silently registering AWS/GCP providers against the wrong,
	// unprefixed issuer).
	for _, called := range fp.issuerURLCalls {
		if called != "test-cluster-demo-ns1" {
			t.Fatalf("expected IssuerURL called with cluster-prefixed realm 'test-cluster-demo-ns1', got %q", called)
		}
	}
	if len(fp.issuerURLCalls) == 0 {
		t.Fatalf("expected IssuerURL to have been called")
	}
}

func TestGcpAccessProfileReconciler_FinalizerAndCleanup(t *testing.T) {
	profile := &myceliamv1.GcpAccessProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "gp1"},
		// Empty on purpose: EnsurePool/DeleteIdp per-project loops must not
		// run (avoiding a real GCP call from this test) while still
		// exercising finalizer add/remove wiring.
		Projects: map[string][]string{},
	}
	c := newTestClient(t, profile)
	r := &GcpAccessProfileReconciler{Deps: &Deps{Client: c, Settings: testSettings(t), OIDC: nil}}

	if _, err := r.Reconcile(context.Background(), reconcileRequest("demo", "gp1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got myceliamv1.GcpAccessProfile
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "demo", Name: "gp1"}, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&got, finalizerName) {
		t.Fatalf("expected finalizer added")
	}
}

func TestSecretReconciler_IgnoresUnrelatedSecrets(t *testing.T) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "unrelated"}}
	c := newTestClient(t, secret)
	r := &SecretReconciler{Deps: &Deps{Client: c, Settings: testSettings(t)}}

	result, err := r.Reconcile(context.Background(), reconcileRequest("demo", "unrelated"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue for an unrelated secret, got %v", result)
	}
}

func TestSecretReconciler_RotatesSignedjwtCert(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "my-app",
			Labels: map[string]string{models.AutoidpLabel: "true", models.ClientTypeLabel: "signedjwt"},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "my-app-oidc-credentials"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": generateTestCertPEM(t)},
	}
	c := newTestClient(t, sa, secret)
	fp := &fakeOIDCProvider{signedjwtClientID: "my-app"}
	r := &SecretReconciler{Deps: &Deps{Client: c, Settings: testSettings(t), OIDC: fp}}

	if _, err := r.Reconcile(context.Background(), reconcileRequest("demo", "my-app-oidc-credentials")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fp.ensureTenantCalls) != 1 {
		t.Fatalf("expected EnsureTenant called once, got %v", fp.ensureTenantCalls)
	}
}

func generateTestCertPEM(t *testing.T) []byte {
	t.Helper()
	certPEM, _, err := certgen.GenerateSelfSignedKeypair("my-app", 2048, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return certPEM
}
