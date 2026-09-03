package keycloak

import (
	"context"
	"testing"

	"myceliam/internal/operr"
)

func TestEnsureAccessScopeCreatesScopeAndAudienceMapper(t *testing.T) {
	admin := newFakeAdmin()
	admin.clientIDs["demo"] = map[string]string{"my-app": "client-id-1"}

	err := ensureAccessScope(context.Background(), admin, "tok", "demo", "my-app", "ap1-my-app", "sts.amazonaws.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.createScopeCalls != 1 {
		t.Fatalf("expected CreateClientScopeWithAudienceMapper called once, got %d", admin.createScopeCalls)
	}
	if !admin.optionalScopes["client-id-1"]["scope-id-ap1-my-app"] {
		t.Fatalf("expected scope attached to client, got %v", admin.optionalScopes)
	}
}

func TestEnsureAccessScopeRetriesOnConcurrentCreateRace(t *testing.T) {
	// Regression coverage for the same race scope.py documents: another
	// reconcile creates this scope first, and Keycloak's 409 must surface as
	// a retryable error rather than an unhandled crash.
	admin := newFakeAdmin()
	admin.createClientScopeErr = errTest("scope already exists")

	err := ensureAccessScope(context.Background(), admin, "tok", "demo", "my-app", "ap1-my-app", "sts.amazonaws.com")
	if _, ok := operr.AsTemporary(err); !ok {
		t.Fatalf("expected *operr.Temporary, got %v", err)
	}
}

func TestEnsureAccessScopeReusesExistingScopeAndAttachment(t *testing.T) {
	admin := newFakeAdmin()
	admin.scopeIDs["demo"] = map[string]string{"ap1-my-app": "scope-id-1"}
	admin.clientIDs["demo"] = map[string]string{"my-app": "client-id-1"}
	admin.optionalScopes["client-id-1"] = map[string]bool{"scope-id-1": true}

	err := ensureAccessScope(context.Background(), admin, "tok", "demo", "my-app", "ap1-my-app", "sts.amazonaws.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.createScopeCalls != 0 {
		t.Fatalf("expected no scope creation, got %d calls", admin.createScopeCalls)
	}
	if admin.attachScopeCalls != 0 {
		t.Fatalf("expected no re-attachment, got %d calls", admin.attachScopeCalls)
	}
}

func TestEnsureAccessScopeUpdatesStaleAudienceOnExistingScope(t *testing.T) {
	// A scope created under an old audience convention (e.g. the
	// namespace-shared myceliam-<ns> value, before per-SA-unique aws
	// audiences existed) must pick up the new value on the next reconcile,
	// not keep whatever it was given at creation forever.
	admin := newFakeAdmin()
	admin.scopeIDs["demo"] = map[string]string{"ap1-my-app": "scope-id-1"}
	admin.clientIDs["demo"] = map[string]string{"my-app": "client-id-1"}
	admin.optionalScopes["client-id-1"] = map[string]bool{"scope-id-1": true}
	admin.scopeAudiences["scope-id-1"] = "myceliam-demo"

	err := ensureAccessScope(context.Background(), admin, "tok", "demo", "my-app", "ap1-my-app", "ap1-my-app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.scopeAudiences["scope-id-1"] != "ap1-my-app" {
		t.Fatalf("expected stale audience updated in place, got %q", admin.scopeAudiences["scope-id-1"])
	}
}

func TestEnsureAccessScopeRetriesWhenClientNotFoundYet(t *testing.T) {
	admin := newFakeAdmin()
	// scope exists, but the client hasn't reconciled yet.
	admin.scopeIDs["demo"] = map[string]string{"ap1-my-app": "scope-id-1"}

	err := ensureAccessScope(context.Background(), admin, "tok", "demo", "my-app", "ap1-my-app", "sts.amazonaws.com")
	temp, ok := operr.AsTemporary(err)
	if !ok {
		t.Fatalf("expected *operr.Temporary, got %v", err)
	}
	if temp.Delay <= 0 {
		t.Fatalf("expected a positive retry delay, got %v", temp.Delay)
	}
}

func TestDeleteAccessScopeNoopWhenAbsent(t *testing.T) {
	admin := newFakeAdmin()
	if err := deleteAccessScope(context.Background(), admin, "tok", "demo", "ap1-my-app"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.deleteScopeCalls != 0 {
		t.Fatalf("expected DeleteClientScope not called, got %d", admin.deleteScopeCalls)
	}
}

func TestDeleteAccessScopeDeletesWhenPresent(t *testing.T) {
	admin := newFakeAdmin()
	admin.scopeIDs["demo"] = map[string]string{"ap1-my-app": "scope-id-1"}

	if err := deleteAccessScope(context.Background(), admin, "tok", "demo", "ap1-my-app"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.deleteScopeCalls != 1 {
		t.Fatalf("expected DeleteClientScope called once, got %d", admin.deleteScopeCalls)
	}
}

func TestProviderEnsureAccessScopeDelegates(t *testing.T) {
	p, admin := testProvider(t)
	admin.clientIDs["demo"] = map[string]string{"my-app": "client-id-1"}

	if err := p.EnsureAccessScope(context.Background(), "demo", "my-app", "ap1-my-app", "sts.amazonaws.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.createScopeCalls != 1 {
		t.Fatalf("expected scope creation delegated through, got %d calls", admin.createScopeCalls)
	}
}

func TestProviderDeleteAccessScopeDelegates(t *testing.T) {
	p, admin := testProvider(t)
	admin.scopeIDs["demo"] = map[string]string{"ap1-my-app": "scope-id-1"}

	if err := p.DeleteAccessScope(context.Background(), "demo", "ap1-my-app"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.deleteScopeCalls != 1 {
		t.Fatalf("expected deletion delegated through, got %d calls", admin.deleteScopeCalls)
	}
}
