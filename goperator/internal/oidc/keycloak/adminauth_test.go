package keycloak

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v13"
)

func testGocloakSecretSource(serverURL string) *gocloakSecretSource {
	return &gocloakSecretSource{
		gc:           gocloak.NewClient(serverURL),
		clientID:     "myceliam-operator",
		clientSecret: "shh",
		realm:        "master",
	}
}

func TestGocloakSecretSourceOmitsScopeWhenUnconfigured(t *testing.T) {
	var gotPath string
	var gotForm url.Values
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = r.ParseForm()
		gotForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "abc", "expires_in": 60}`))
	}))
	defer server.Close()

	src := testGocloakSecretSource(server.URL)
	accessToken, expiresIn, err := src.fetchToken(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if accessToken != "abc" || expiresIn != 60 {
		t.Fatalf("unexpected token/expiresIn: %q %d", accessToken, expiresIn)
	}
	if gotPath != "/realms/master/protocol/openid-connect/token" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotForm.Has("scope") {
		t.Fatalf("expected no scope param, got %v", gotForm.Get("scope"))
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("myceliam-operator:shh"))
	if gotAuth != wantAuth {
		t.Fatalf("unexpected Authorization header: %q", gotAuth)
	}
}

func TestGocloakSecretSourcePassesScopeWhenConfigured(t *testing.T) {
	var gotForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "abc", "expires_in": 60}`))
	}))
	defer server.Close()

	src := testGocloakSecretSource(server.URL)
	if _, _, err := src.fetchToken(context.Background(), "sts.amazonaws.com gcp-sts"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotForm.Get("scope") != "sts.amazonaws.com gcp-sts" {
		t.Fatalf("unexpected scope: %v", gotForm.Get("scope"))
	}
}

func TestGocloakSecretSourceSurfacesFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer server.Close()

	src := testGocloakSecretSource(server.URL)
	_, _, err := src.fetchToken(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected error mentioning the 401 status, got %v", err)
	}
}

func TestAdminAuthCachesTokenUntilExpiry(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "tok", "expires_in": 3600}`))
	}))
	defer server.Close()

	src := testGocloakSecretSource(server.URL)
	auth := newAdminAuth(src, "")

	for range 3 {
		if _, err := auth.Token(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 fetch (subsequent calls served from cache), got %d", calls)
	}
}

func TestAdminAuthAndOperatorAuthCacheIndependently(t *testing.T) {
	// Regression coverage: KeycloakProvider.auth (scope "") and .operatorAuth
	// (scope Settings.KeycloakOperatorScope) share the same underlying
	// source/credential but must never share a cached token, since Keycloak
	// mints a different token per requested scope.
	var gotScopes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotScopes = append(gotScopes, r.Form.Get("scope"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "tok", "expires_in": 3600}`))
	}))
	defer server.Close()

	src := testGocloakSecretSource(server.URL)
	adminAuth := newAdminAuth(src, "")
	operatorAuth := newAdminAuth(src, "cloud-federation")

	if _, err := adminAuth.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := operatorAuth.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gotScopes) != 2 || gotScopes[0] != "" || gotScopes[1] != "cloud-federation" {
		t.Fatalf("expected one no-scope fetch then one scoped fetch, got %v", gotScopes)
	}
}

// fakeSlowTokenSource lets tests assert on expiry-driven refresh timing
// without a real clock dependency in production code.
type fakeCountingSource struct {
	calls     int
	expiresIn int
}

func (f *fakeCountingSource) fetchToken(context.Context, string) (string, int, error) {
	f.calls++
	return "tok", f.expiresIn, nil
}

func TestAdminAuthRefetchesAfterExpiry(t *testing.T) {
	src := &fakeCountingSource{expiresIn: 0} // expiresAt lands tokenExpiryBuffer (10s) in the past — already expired on arrival
	auth := newAdminAuth(src, "")

	if _, err := auth.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := auth.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src.calls != 2 {
		t.Fatalf("expected 2 fetches for a token that expires almost immediately, got %d", src.calls)
	}
}
