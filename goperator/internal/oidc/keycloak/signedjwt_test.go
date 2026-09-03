package keycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"myceliam/internal/certgen"
)

func testSignedJWTSource(t *testing.T, serverURL string, lifetime time.Duration) *signedJWTSource {
	t.Helper()
	_, keyPEM, err := certgen.GenerateSelfSignedKeypair("myceliam-operator", 2048, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	src, err := newSignedJWTSource(serverURL, "myceliam-operator", "master", true, keyPEM, lifetime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return src
}

func TestBuildClientAssertionClaimsAreCorrect(t *testing.T) {
	src := testSignedJWTSource(t, "https://kc.example.com", 45*time.Second)

	tokenStr, err := src.buildClientAssertion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := jwt.Parse(tokenStr, func(tok *jwt.Token) (any, error) {
		return &src.privateKey.PublicKey, nil
	}, jwt.WithAudience("https://kc.example.com/realms/master/protocol/openid-connect/token"))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	// No kid header: Keycloak's single-certificate client-jwt authenticator
	// needs none, and setting one that doesn't match Keycloak's own internal
	// bookkeeping breaks it — confirmed empirically against a real Keycloak
	// instance (see newSignedJWTSource's doc comment).
	if _, ok := parsed.Header["kid"]; ok {
		t.Fatalf("expected no kid header, got %v", parsed.Header["kid"])
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != "myceliam-operator" || claims["sub"] != "myceliam-operator" {
		t.Fatalf("unexpected iss/sub: %v/%v", claims["iss"], claims["sub"])
	}
	exp, _ := claims.GetExpirationTime()
	iat, _ := claims.GetIssuedAt()
	if exp.Sub(iat.Time) != 45*time.Second {
		t.Fatalf("unexpected exp-iat delta: %v", exp.Sub(iat.Time))
	}
	if claims["jti"] == "" || claims["jti"] == nil {
		t.Fatalf("expected non-empty jti")
	}
}

func TestBuildClientAssertionJTIIsUniquePerCall(t *testing.T) {
	src := testSignedJWTSource(t, "https://kc.example.com", time.Minute)

	first, err := src.buildClientAssertion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := src.buildClientAssertion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	firstClaims, _ := jwt.Parse(first, func(*jwt.Token) (any, error) { return &src.privateKey.PublicKey, nil })
	secondClaims, _ := jwt.Parse(second, func(*jwt.Token) (any, error) { return &src.privateKey.PublicKey, nil })
	if firstClaims.Claims.(jwt.MapClaims)["jti"] == secondClaims.Claims.(jwt.MapClaims)["jti"] {
		t.Fatalf("expected distinct jti values")
	}
}

func TestFetchTokenPostsSignedAssertionAndReturnsToken(t *testing.T) {
	var gotForm map[string][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/master/protocol/openid-connect/token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_ = r.ParseForm()
		gotForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "abc", "expires_in": 60}`))
	}))
	defer server.Close()

	src := testSignedJWTSource(t, server.URL, time.Minute)

	accessToken, expiresIn, err := src.fetchToken(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if accessToken != "abc" || expiresIn != 60 {
		t.Fatalf("unexpected token/expiresIn: %q %d", accessToken, expiresIn)
	}
	if gotForm["grant_type"][0] != "client_credentials" {
		t.Fatalf("unexpected grant_type: %v", gotForm["grant_type"])
	}
	if gotForm["client_assertion_type"][0] != clientAssertionType {
		t.Fatalf("unexpected client_assertion_type: %v", gotForm["client_assertion_type"])
	}
	if _, err := jwt.Parse(gotForm["client_assertion"][0], func(*jwt.Token) (any, error) {
		return &src.privateKey.PublicKey, nil
	}); err != nil {
		t.Fatalf("posted assertion did not parse: %v", err)
	}
	if _, ok := gotForm["scope"]; ok {
		t.Fatalf("expected no scope param, got %v", gotForm["scope"])
	}
}

func TestFetchTokenPassesScopeWhenConfigured(t *testing.T) {
	var gotForm map[string][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "abc", "expires_in": 60}`))
	}))
	defer server.Close()

	src := testSignedJWTSource(t, server.URL, time.Minute)

	if _, _, err := src.fetchToken(context.Background(), "cloud-federation"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotForm["scope"][0] != "cloud-federation" {
		t.Fatalf("unexpected scope: %v", gotForm["scope"])
	}
}

func TestFetchTokenSurfacesConnectionFailure(t *testing.T) {
	src := testSignedJWTSource(t, "http://127.0.0.1:0", time.Minute) // nothing listening

	_, _, err := src.fetchToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestFetchTokenSurfacesResponseErrorDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid_client"))
	}))
	defer server.Close()

	src := testSignedJWTSource(t, server.URL, time.Minute)

	_, _, err := src.fetchToken(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("expected error mentioning response body, got %v", err)
	}
}
