package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"myceliam/internal/config"
	"myceliam/internal/oidc"
	"myceliam/internal/operr"
)

// recordedCall captures one non-GET request the fake GCP API server received.
type recordedCall struct {
	method string
	path   string
	query  url.Values
	body   map[string]any
}

// fakeGCPServer serves canned GET responses by path suffix and records every
// write (POST/PATCH/DELETE) — the Go equivalent of the Python suite's
// side_effect-list mocking of requests.get/post/patch/delete, but dispatched
// by path instead of call order, so scenarios read declaratively.
type fakeGCPServer struct {
	t *testing.T

	jwksStatus int
	jwksBody   string

	poolStatus     int
	poolBody       map[string]any
	providerStatus int
	providerBody   map[string]any

	writeStatus int // status returned for every POST/PATCH/DELETE, default 200

	calls []recordedCall
}

func newFakeGCPServer(t *testing.T) *fakeGCPServer {
	return &fakeGCPServer{t: t, jwksStatus: 200, jwksBody: `{"keys": []}`, writeStatus: 200}
}

func (f *fakeGCPServer) start() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/certs") {
			w.WriteHeader(f.jwksStatus)
			_, _ = w.Write([]byte(f.jwksBody))
			return
		}

		if r.Method == http.MethodGet {
			if strings.Contains(r.URL.Path, "/providers/") {
				w.WriteHeader(f.providerStatus)
				_ = json.NewEncoder(w).Encode(f.providerBody)
				return
			}
			w.WriteHeader(f.poolStatus)
			_ = json.NewEncoder(w).Encode(f.poolBody)
			return
		}

		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.calls = append(f.calls, recordedCall{method: r.Method, path: r.URL.Path, query: r.URL.Query(), body: body})
		w.WriteHeader(f.writeStatus)
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
}

func testSettings(t *testing.T, overrides map[string]string) *config.Settings {
	t.Helper()
	t.Setenv("MYCELIAM_KEYCLOAK_URL", "https://kc.example.com")
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

func withFakeGCPToken(t *testing.T) {
	t.Helper()
	original := getGCPAccessToken
	getGCPAccessToken = func(context.Context, *config.Settings, oidc.Provider) (string, error) { return "gcp-token", nil }
	t.Cleanup(func() { getGCPAccessToken = original })
}

func withIAMAPIBase(t *testing.T, base string) {
	t.Helper()
	original := iamAPIBase
	iamAPIBase = base
	t.Cleanup(func() { iamAPIBase = original })
}

func TestEnsurePoolCreatesWhenAbsent(t *testing.T) {
	withFakeGCPToken(t)
	fake := newFakeGCPServer(t)
	fake.poolStatus = 404
	server := fake.start()
	defer server.Close()
	withIAMAPIBase(t, server.URL)

	if err := EnsurePool(context.Background(), "proj-1", testSettings(t, nil), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.calls) != 1 || fake.calls[0].method != http.MethodPost {
		t.Fatalf("expected 1 POST call, got %+v", fake.calls)
	}
	if !strings.Contains(fake.calls[0].path, "workloadIdentityPools") {
		t.Fatalf("unexpected path: %s", fake.calls[0].path)
	}
}

func TestEnsurePoolNoopWhenActive(t *testing.T) {
	withFakeGCPToken(t)
	fake := newFakeGCPServer(t)
	fake.poolStatus = 200
	fake.poolBody = map[string]any{"state": "ACTIVE"}
	server := fake.start()
	defer server.Close()
	withIAMAPIBase(t, server.URL)

	if err := EnsurePool(context.Background(), "proj-1", testSettings(t, nil), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no write calls, got %+v", fake.calls)
	}
}

func TestEnsurePoolUndeletesWhenDeleted(t *testing.T) {
	withFakeGCPToken(t)
	fake := newFakeGCPServer(t)
	fake.poolStatus = 200
	fake.poolBody = map[string]any{"state": "DELETED"}
	server := fake.start()
	defer server.Close()
	withIAMAPIBase(t, server.URL)

	err := EnsurePool(context.Background(), "proj-1", testSettings(t, nil), nil)
	if _, ok := operr.AsTemporary(err); !ok {
		t.Fatalf("expected *operr.Temporary, got %v", err)
	}
	if len(fake.calls) != 1 || !strings.HasSuffix(fake.calls[0].path, ":undelete") {
		t.Fatalf("expected 1 undelete call, got %+v", fake.calls)
	}
}

func TestEnsureIdpCreatesProviderWhenAbsent(t *testing.T) {
	withFakeGCPToken(t)
	fake := newFakeGCPServer(t)
	fake.jwksStatus = 200
	fake.jwksBody = `{"keys": []}`
	fake.providerStatus = 404
	server := fake.start()
	defer server.Close()
	withIAMAPIBase(t, server.URL)

	settings := testSettings(t, nil)
	issuerURL := server.URL + "/realms/demo"

	err := EnsureIdp(context.Background(), "proj-1", "demo", issuerURL, "sts.googleapis.com", settings, KindOIDC, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 write call, got %+v", fake.calls)
	}
	call := fake.calls[0]
	if call.query.Get("workloadIdentityPoolProviderId") != "test-cluster-demo-oidc" {
		t.Fatalf("unexpected provider id: %v", call.query)
	}
	oidcPayload := call.body["oidc"].(map[string]any)
	if oidcPayload["issuerUri"] != issuerURL {
		t.Fatalf("unexpected issuerUri: %v", oidcPayload["issuerUri"])
	}
	if oidcPayload["jwksJson"] != `{"keys": []}` {
		t.Fatalf("unexpected jwksJson: %v", oidcPayload["jwksJson"])
	}
	attrMapping := call.body["attributeMapping"].(map[string]any)
	if attrMapping["google.subject"] != "assertion.azp" {
		t.Fatalf("unexpected attributeMapping: %v", attrMapping)
	}
}

func TestEnsureIdpSkipsJWKSFetchAndUsesSubjectClaimForSpiffe(t *testing.T) {
	withFakeGCPToken(t)
	fake := newFakeGCPServer(t)
	fake.providerStatus = 404
	server := fake.start()
	defer server.Close()
	withIAMAPIBase(t, server.URL)

	settings := testSettings(t, nil)
	err := EnsureIdp(context.Background(), "proj-1", "demo", "https://spire1-oidc.example.com", "myceliam-demo", settings, KindSpiffe, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	call := fake.calls[0]
	if call.query.Get("workloadIdentityPoolProviderId") != "test-cluster-demo-spiffe" {
		t.Fatalf("unexpected provider id: %v", call.query)
	}
	oidcPayload := call.body["oidc"].(map[string]any)
	if _, ok := oidcPayload["jwksJson"]; ok {
		t.Fatalf("expected no jwksJson for spiffe kind, got %v", oidcPayload)
	}
	attrMapping := call.body["attributeMapping"].(map[string]any)
	if attrMapping["google.subject"] != "assertion.sub" {
		t.Fatalf("unexpected attributeMapping: %v", attrMapping)
	}
}

func TestEnsureIdpUpdatesProviderWhenPresent(t *testing.T) {
	withFakeGCPToken(t)
	fake := newFakeGCPServer(t)
	fake.providerStatus = 200
	fake.providerBody = map[string]any{"state": "ACTIVE"}
	server := fake.start()
	defer server.Close()
	withIAMAPIBase(t, server.URL)

	settings := testSettings(t, nil)
	err := EnsureIdp(context.Background(), "proj-1", "demo", server.URL+"/realms/demo", "sts.googleapis.com", settings, KindOIDC, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.calls) != 1 || fake.calls[0].method != http.MethodPatch {
		t.Fatalf("expected 1 PATCH call, got %+v", fake.calls)
	}
}

func TestEnsureIdpUndeletesProviderWhenDeleted(t *testing.T) {
	withFakeGCPToken(t)
	fake := newFakeGCPServer(t)
	fake.providerStatus = 200
	fake.providerBody = map[string]any{"state": "DELETED"}
	server := fake.start()
	defer server.Close()
	withIAMAPIBase(t, server.URL)

	settings := testSettings(t, nil)
	err := EnsureIdp(context.Background(), "proj-1", "demo", server.URL+"/realms/demo", "sts.googleapis.com", settings, KindOIDC, nil)
	if _, ok := operr.AsTemporary(err); !ok {
		t.Fatalf("expected *operr.Temporary, got %v", err)
	}
	if len(fake.calls) != 1 || !strings.HasSuffix(fake.calls[0].path, ":undelete") {
		t.Fatalf("expected 1 undelete call, got %+v", fake.calls)
	}
}

func TestProviderIDTruncatesLongNamespaceReservingRoomForKindSuffix(t *testing.T) {
	settings := testSettings(t, nil)
	id := providerID(strings.Repeat("a", 40), KindSpiffe, settings)
	if len(id) > 32 {
		t.Fatalf("expected id <= 32 chars, got %d: %s", len(id), id)
	}
	if !strings.HasSuffix(id, "-spiffe") {
		t.Fatalf("expected -spiffe suffix, got %s", id)
	}
}

func TestProviderIDDiffersByKindForSameNamespace(t *testing.T) {
	settings := testSettings(t, nil)
	oidcID := providerID("demo", KindOIDC, settings)
	spiffeID := providerID("demo", KindSpiffe, settings)
	if oidcID != "test-cluster-demo-oidc" || spiffeID != "test-cluster-demo-spiffe" {
		t.Fatalf("unexpected ids: %s %s", oidcID, spiffeID)
	}
}

func TestProviderIDUsesClusterID(t *testing.T) {
	settings := testSettings(t, map[string]string{"CLUSTER_ID": "other-cluster"})
	if got := providerID("demo", KindOIDC, settings); got != "other-cluster-demo-oidc" {
		t.Fatalf("unexpected id: %s", got)
	}
}

func TestDeleteIdpIgnores404(t *testing.T) {
	withFakeGCPToken(t)
	fake := newFakeGCPServer(t)
	fake.writeStatus = 404
	server := fake.start()
	defer server.Close()
	withIAMAPIBase(t, server.URL)

	if err := DeleteIdp(context.Background(), "proj-1", "demo", testSettings(t, nil), KindOIDC, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteIdpUsesKindScopedProviderID(t *testing.T) {
	withFakeGCPToken(t)
	fake := newFakeGCPServer(t)
	server := fake.start()
	defer server.Close()
	withIAMAPIBase(t, server.URL)

	if err := DeleteIdp(context.Background(), "proj-1", "demo", testSettings(t, nil), KindSpiffe, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.calls) != 1 || !strings.HasSuffix(fake.calls[0].path, "/providers/test-cluster-demo-spiffe") {
		t.Fatalf("unexpected calls: %+v", fake.calls)
	}
}

// fakeIAMPolicyServer serves projectNumber lookups (Cloud Resource Manager)
// and getIamPolicy/setIamPolicy calls (IAM) from a single httptest.Server —
// GrantImpersonation/RevokeImpersonation talk to both hosts, so tests point
// both iamAPIBase and cloudResourceManagerAPIBase at it.
type fakeIAMPolicyServer struct {
	projectNumber   string
	policy          iamPolicy
	getPolicyStatus int // 0 defaults to 200
	setCalls        []map[string]any
}

func (f *fakeIAMPolicyServer) start() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, ":getIamPolicy"):
			if f.getPolicyStatus != 0 && f.getPolicyStatus != http.StatusOK {
				w.WriteHeader(f.getPolicyStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(f.policy)
		case strings.Contains(r.URL.Path, ":setIamPolicy"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.setCalls = append(f.setCalls, body)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default: // Cloud Resource Manager project-number lookup
			_ = json.NewEncoder(w).Encode(map[string]string{"projectNumber": f.projectNumber})
		}
	}))
}

func withImpersonationServer(t *testing.T, fake *fakeIAMPolicyServer) {
	t.Helper()
	server := fake.start()
	t.Cleanup(server.Close)
	origIAM, origCRM := iamAPIBase, cloudResourceManagerAPIBase
	iamAPIBase, cloudResourceManagerAPIBase = server.URL, server.URL
	t.Cleanup(func() { iamAPIBase, cloudResourceManagerAPIBase = origIAM, origCRM })
}

func expectedPrincipal(projectNumber, poolID, subject string) string {
	return "principal://iam.googleapis.com/projects/" + projectNumber +
		"/locations/global/workloadIdentityPools/" + poolID + "/subject/" + subject
}

func TestGrantImpersonationAddsMemberToNewBinding(t *testing.T) {
	withFakeGCPToken(t)
	fake := &fakeIAMPolicyServer{projectNumber: "123456", policy: iamPolicy{}}
	withImpersonationServer(t, fake)

	err := GrantImpersonation(context.Background(), "target@proj.iam.gserviceaccount.com", "pool-proj", "my-app", testSettings(t, nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.setCalls) != 1 {
		t.Fatalf("expected 1 setIamPolicy call, got %d", len(fake.setCalls))
	}
	policy := fake.setCalls[0]["policy"].(map[string]any)
	bindings := policy["bindings"].([]any)
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %+v", bindings)
	}
	binding := bindings[0].(map[string]any)
	if binding["role"] != workloadIdentityUserRole {
		t.Fatalf("unexpected role: %v", binding["role"])
	}
	members := binding["members"].([]any)
	want := expectedPrincipal("123456", "myceliam-operator", "my-app")
	if len(members) != 1 || members[0] != want {
		t.Fatalf("unexpected members: %v (want %q)", members, want)
	}
}

func TestGrantImpersonationAppendsToExistingBinding(t *testing.T) {
	withFakeGCPToken(t)
	fake := &fakeIAMPolicyServer{
		projectNumber: "123456",
		policy: iamPolicy{Bindings: []iamBinding{
			{Role: workloadIdentityUserRole, Members: []string{"principal://existing"}},
		}},
	}
	withImpersonationServer(t, fake)

	err := GrantImpersonation(context.Background(), "target@proj.iam.gserviceaccount.com", "pool-proj", "my-app", testSettings(t, nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	policy := fake.setCalls[0]["policy"].(map[string]any)
	bindings := policy["bindings"].([]any)
	binding := bindings[0].(map[string]any)
	members := binding["members"].([]any)
	if len(members) != 2 {
		t.Fatalf("expected existing member preserved plus new one, got %v", members)
	}
}

func TestGrantImpersonationIsIdempotent(t *testing.T) {
	withFakeGCPToken(t)
	member := expectedPrincipal("123456", "myceliam-operator", "my-app")
	fake := &fakeIAMPolicyServer{
		projectNumber: "123456",
		policy: iamPolicy{Bindings: []iamBinding{
			{Role: workloadIdentityUserRole, Members: []string{member}},
		}},
	}
	withImpersonationServer(t, fake)

	err := GrantImpersonation(context.Background(), "target@proj.iam.gserviceaccount.com", "pool-proj", "my-app", testSettings(t, nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.setCalls) != 0 {
		t.Fatalf("expected no setIamPolicy call when member already present, got %d", len(fake.setCalls))
	}
}

func TestGrantImpersonationRejectsMissingServiceAccount(t *testing.T) {
	withFakeGCPToken(t)
	fake := &fakeIAMPolicyServer{projectNumber: "123456", getPolicyStatus: http.StatusNotFound}
	withImpersonationServer(t, fake)

	err := GrantImpersonation(context.Background(), "missing@proj.iam.gserviceaccount.com", "pool-proj", "my-app", testSettings(t, nil), nil)
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestRevokeImpersonationRemovesMemberOnly(t *testing.T) {
	withFakeGCPToken(t)
	member := expectedPrincipal("123456", "myceliam-operator", "my-app")
	fake := &fakeIAMPolicyServer{
		projectNumber: "123456",
		policy: iamPolicy{Bindings: []iamBinding{
			{Role: workloadIdentityUserRole, Members: []string{member, "principal://someone-else"}},
		}},
	}
	withImpersonationServer(t, fake)

	err := RevokeImpersonation(context.Background(), "target@proj.iam.gserviceaccount.com", "pool-proj", "my-app", testSettings(t, nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	policy := fake.setCalls[0]["policy"].(map[string]any)
	bindings := policy["bindings"].([]any)
	binding := bindings[0].(map[string]any)
	members := binding["members"].([]any)
	if len(members) != 1 || members[0] != "principal://someone-else" {
		t.Fatalf("expected only the other member to remain, got %v", members)
	}
}

func TestRevokeImpersonationNoopWhenAbsent(t *testing.T) {
	withFakeGCPToken(t)
	fake := &fakeIAMPolicyServer{projectNumber: "123456", policy: iamPolicy{}}
	withImpersonationServer(t, fake)

	err := RevokeImpersonation(context.Background(), "target@proj.iam.gserviceaccount.com", "pool-proj", "my-app", testSettings(t, nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.setCalls) != 0 {
		t.Fatalf("expected no setIamPolicy call, got %d", len(fake.setCalls))
	}
}

func TestRevokeImpersonationNoopWhenServiceAccountGone(t *testing.T) {
	withFakeGCPToken(t)
	fake := &fakeIAMPolicyServer{projectNumber: "123456", getPolicyStatus: http.StatusNotFound}
	withImpersonationServer(t, fake)

	if err := RevokeImpersonation(context.Background(), "gone@proj.iam.gserviceaccount.com", "pool-proj", "my-app", testSettings(t, nil), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
