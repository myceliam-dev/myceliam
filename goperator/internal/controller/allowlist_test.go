package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	myceliamv1 "myceliam/api/v1"
	"myceliam/internal/models"
	"myceliam/internal/operr"
)

func newAllowlist(namespaces ...string) *myceliamv1.AutoidpAllowlist {
	return &myceliamv1.AutoidpAllowlist{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: myceliamv1.AutoidpAllowlistNamespace,
			Name:      myceliamv1.AutoidpAllowlistName,
		},
		Namespaces: namespaces,
	}
}

func TestIsNamespaceAllowed_AbsentMeansAllowed(t *testing.T) {
	c := newTestClient(t)
	deps := &Deps{Client: c, Settings: testSettings(t)}

	allowed, err := isNamespaceAllowed(context.Background(), deps, "demo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected allowed=true when no AutoidpAllowlist exists")
	}
}

func TestIsNamespaceAllowed_ListedNamespace(t *testing.T) {
	c := newTestClient(t, newAllowlist("demo", "other"))
	deps := &Deps{Client: c, Settings: testSettings(t)}

	allowed, err := isNamespaceAllowed(context.Background(), deps, "demo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected allowed=true for a listed namespace")
	}
}

func TestIsNamespaceAllowed_UnlistedNamespace(t *testing.T) {
	c := newTestClient(t, newAllowlist("other"))
	deps := &Deps{Client: c, Settings: testSettings(t)}

	allowed, err := isNamespaceAllowed(context.Background(), deps, "demo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("expected allowed=false for an unlisted namespace")
	}
}

func TestRequireNamespaceAllowed_PermanentErrorWhenNotAllowed(t *testing.T) {
	c := newTestClient(t, newAllowlist("other"))
	deps := &Deps{Client: c, Settings: testSettings(t)}

	err := requireNamespaceAllowed(context.Background(), deps, "demo", "my-app")
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestServiceAccountReconciler_BlocksProvisioningWhenNamespaceNotAllowed(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "my-app",
			Labels:     map[string]string{models.AutoidpLabel: "true", models.ClientTypeLabel: "secret"},
			Finalizers: []string{finalizerName},
		},
	}
	c := newTestClient(t, sa, newAllowlist("some-other-namespace"))
	fp := &fakeOIDCProvider{secretClientID: "my-app", secretClientSecret: "s3cr3t"}
	r := &ServiceAccountReconciler{Deps: &Deps{Client: c, Settings: testSettings(t), OIDC: fp}}

	result, err := r.Reconcile(context.Background(), reconcileRequest("demo", "my-app"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected periodic requeue even when blocked by the allowlist, got %v", result)
	}
	if len(fp.ensureTenantCalls) != 0 {
		t.Fatalf("expected EnsureTenant never called for a non-allowlisted namespace, got %v", fp.ensureTenantCalls)
	}
}

func TestServiceAccountReconciler_CleanupIgnoresAllowlist(t *testing.T) {
	now := metav1.Now()
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "my-app",
			Labels:            map[string]string{models.AutoidpLabel: "true", models.ClientTypeLabel: "secret"},
			Finalizers:        []string{finalizerName},
			DeletionTimestamp: &now,
		},
	}
	// Namespace "demo" is deliberately NOT in the allowlist — cleanup must
	// still run to completion regardless (see AutoidpAllowlist's doc comment:
	// the allowlist only ever gates provisioning, never cleanup).
	c := newTestClient(t, sa, newAllowlist("some-other-namespace"))
	fp := &fakeOIDCProvider{}
	r := &ServiceAccountReconciler{Deps: &Deps{Client: c, Settings: testSettings(t), OIDC: fp}}

	if _, err := r.Reconcile(context.Background(), reconcileRequest("demo", "my-app")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fp.deleteClientCalls) != 1 {
		t.Fatalf("expected DeleteClient called despite namespace not being allowlisted, got %v", fp.deleteClientCalls)
	}
}

func TestAutoidpAllowlistReconciler_PokesMatchingServiceAccounts(t *testing.T) {
	allowlist := newAllowlist("demo")
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "my-app",
			Labels: map[string]string{models.AutoidpLabel: "true"},
		},
	}
	unrelated := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "not-autoidp"},
	}
	c := newTestClient(t, allowlist, sa, unrelated)
	r := &AutoidpAllowlistReconciler{Deps: &Deps{Client: c, Settings: testSettings(t)}}

	_, err := r.Reconcile(context.Background(), reconcileRequest(myceliamv1.AutoidpAllowlistNamespace, myceliamv1.AutoidpAllowlistName))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got corev1.ServiceAccount
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "demo", Name: "my-app"}, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Annotations[allowlistObservedGenerationAnnotation] != allowlist.ResourceVersion {
		t.Fatalf("expected poke annotation set to the allowlist's resourceVersion, got %+v", got.Annotations)
	}

	var gotUnrelated corev1.ServiceAccount
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "demo", Name: "not-autoidp"}, &gotUnrelated); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := gotUnrelated.Annotations[allowlistObservedGenerationAnnotation]; ok {
		t.Fatalf("expected non-autoidp SA to be left untouched")
	}
}

func TestAutoidpAllowlistReconciler_IgnoresOtherInstances(t *testing.T) {
	wrongName := &myceliamv1.AutoidpAllowlist{
		ObjectMeta: metav1.ObjectMeta{Namespace: myceliamv1.AutoidpAllowlistNamespace, Name: "not-the-singleton"},
		Namespaces: []string{"demo"},
	}
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "my-app",
			Labels: map[string]string{models.AutoidpLabel: "true"},
		},
	}
	c := newTestClient(t, wrongName, sa)
	r := &AutoidpAllowlistReconciler{Deps: &Deps{Client: c, Settings: testSettings(t)}}

	_, err := r.Reconcile(context.Background(), reconcileRequest(myceliamv1.AutoidpAllowlistNamespace, "not-the-singleton"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got corev1.ServiceAccount
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "demo", Name: "my-app"}, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got.Annotations[allowlistObservedGenerationAnnotation]; ok {
		t.Fatalf("expected no poke for a non-singleton AutoidpAllowlist instance")
	}
}
