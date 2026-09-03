package keycloak

import (
	"context"
	"testing"

	"myceliam/internal/config"
	"myceliam/internal/httpx"
	"myceliam/internal/models"
	"myceliam/internal/operr"
)

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

func testProvider(t *testing.T) (*KeycloakProvider, *fakeAdmin) {
	t.Helper()
	admin := newFakeAdmin()
	p := &KeycloakProvider{
		settings:     testSettings(t),
		admin:        admin,
		auth:         &fakeTokenProvider{token: "admin-token"},
		operatorAuth: &fakeTokenProvider{token: "operator-token"},
		httpClient:   httpx.NewClient(true),
	}
	return p, admin
}

func TestEnsureTenantCreatesWhenMissing(t *testing.T) {
	p, admin := testProvider(t)
	if err := p.EnsureTenant(context.Background(), "demo"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.createRealmCalls != 1 {
		t.Fatalf("expected CreateRealm called once, got %d", admin.createRealmCalls)
	}
	if !admin.realms["demo"] {
		t.Fatalf("expected realm 'demo' to exist")
	}
}

func TestEnsureTenantRetriesWhenCreateRacesWithAnotherReconcile(t *testing.T) {
	// Regression coverage for the same race pythonoperator's client.py
	// documents (two SAs landing in a brand-new namespace at once): the
	// loser's CreateRealm fails (409 from Keycloak), and that must surface as
	// a retryable error, not an unhandled crash.
	p, admin := testProvider(t)
	admin.createRealmErr = errTest("realm already exists")

	err := p.EnsureTenant(context.Background(), "demo")
	if _, ok := operr.AsTemporary(err); !ok {
		t.Fatalf("expected *operr.Temporary, got %v", err)
	}
}

func TestEnsureTenantNoopWhenPresent(t *testing.T) {
	p, admin := testProvider(t)
	admin.realms["demo"] = true
	admin.realmAttributes["demo"] = "test-cluster"

	if err := p.EnsureTenant(context.Background(), "demo"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.createRealmCalls != 0 {
		t.Fatalf("expected CreateRealm not called, got %d calls", admin.createRealmCalls)
	}
}

func TestEnsureTenantCreationStampsClusterID(t *testing.T) {
	p, admin := testProvider(t)
	if err := p.EnsureTenant(context.Background(), "demo"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.realmAttributes["demo"] != "test-cluster" {
		t.Fatalf("expected realm stamped with cluster-id, got %q", admin.realmAttributes["demo"])
	}
}

func TestEnsureTenantRefusesRealmOwnedByAnotherCluster(t *testing.T) {
	p, admin := testProvider(t)
	admin.realms["demo"] = true
	admin.realmAttributes["demo"] = "other-cluster"

	err := p.EnsureTenant(context.Background(), "demo")
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestEnsureTenantRefusesRealmWithNoClusterIDAttribute(t *testing.T) {
	p, admin := testProvider(t)
	admin.realms["demo"] = true
	// Deliberately no admin.realmAttributes["demo"] entry — simulates a realm
	// that predates this feature or was created out-of-band.

	err := p.EnsureTenant(context.Background(), "demo")
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestDeleteTenantRefusesRealmOwnedByAnotherCluster(t *testing.T) {
	p, admin := testProvider(t)
	admin.realms["demo"] = true
	admin.realmAttributes["demo"] = "other-cluster"

	err := p.DeleteTenant(context.Background(), "demo")
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
	if admin.deleteRealmCalls != 0 {
		t.Fatalf("expected DeleteRealm not called, got %d calls", admin.deleteRealmCalls)
	}
}

func TestEnsureSecretClientCreatesAndGeneratesSecret(t *testing.T) {
	p, admin := testProvider(t)
	spec := &models.ClientSpec{
		Realm: "demo", ClientName: "my-app", ClientType: models.ClientTypeSecret,
		CredentialsSecretName: "my-app-oidc-credentials",
	}

	clientID, clientSecret, err := p.EnsureSecretClient(context.Background(), spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clientID != "my-app" || clientSecret != "generated-secret" {
		t.Fatalf("unexpected result: %q %q", clientID, clientSecret)
	}
	if admin.lastCreateClientPayload.ClientID != "my-app" || !admin.lastCreateClientPayload.ServiceAccountsEnabled {
		t.Fatalf("unexpected create payload: %+v", admin.lastCreateClientPayload)
	}
	if admin.generateSecretCalls != 1 {
		t.Fatalf("expected GenerateClientSecret called once, got %d", admin.generateSecretCalls)
	}
}

func TestEnsureSecretClientReusesExistingClient(t *testing.T) {
	p, admin := testProvider(t)
	admin.clientIDs["demo"] = map[string]string{"my-app": "existing-id"}
	admin.clientPayloads["existing-id"] = ClientPayload{Attributes: map[string]string{ClusterIDAttribute: "test-cluster"}}
	admin.clientSecrets["existing-id"] = "existing-secret"

	spec := &models.ClientSpec{
		Realm: "demo", ClientName: "my-app", ClientType: models.ClientTypeSecret,
		CredentialsSecretName: "my-app-oidc-credentials",
	}

	_, clientSecret, err := p.EnsureSecretClient(context.Background(), spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.createClientCalls != 0 {
		t.Fatalf("expected CreateClient not called, got %d", admin.createClientCalls)
	}
	if admin.updateClientCalls != 1 {
		t.Fatalf("expected UpdateClient called once, got %d", admin.updateClientCalls)
	}
	if clientSecret != "existing-secret" {
		t.Fatalf("expected existing secret reused, got %q", clientSecret)
	}
}

func TestEnsureSecretClientCreationStampsClusterID(t *testing.T) {
	p, admin := testProvider(t)
	spec := &models.ClientSpec{
		Realm: "demo", ClientName: "my-app", ClientType: models.ClientTypeSecret,
		CredentialsSecretName: "my-app-oidc-credentials",
	}
	if _, _, err := p.EnsureSecretClient(context.Background(), spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.lastCreateClientPayload.Attributes[ClusterIDAttribute] != "test-cluster" {
		t.Fatalf("expected client stamped with cluster-id, got %+v", admin.lastCreateClientPayload.Attributes)
	}
}

func TestEnsureSecretClientRefusesClientOwnedByAnotherCluster(t *testing.T) {
	p, admin := testProvider(t)
	admin.clientIDs["demo"] = map[string]string{"my-app": "existing-id"}
	admin.clientPayloads["existing-id"] = ClientPayload{Attributes: map[string]string{ClusterIDAttribute: "other-cluster"}}

	spec := &models.ClientSpec{
		Realm: "demo", ClientName: "my-app", ClientType: models.ClientTypeSecret,
		CredentialsSecretName: "my-app-oidc-credentials",
	}
	_, _, err := p.EnsureSecretClient(context.Background(), spec)
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
	if admin.updateClientCalls != 0 {
		t.Fatalf("expected UpdateClient not called, got %d", admin.updateClientCalls)
	}
}

func TestEnsureSecretClientRefusesClientWithNoClusterIDAttribute(t *testing.T) {
	p, admin := testProvider(t)
	admin.clientIDs["demo"] = map[string]string{"my-app": "existing-id"}
	// Deliberately no Attributes set — simulates a client that predates this
	// feature or was created out-of-band.

	spec := &models.ClientSpec{
		Realm: "demo", ClientName: "my-app", ClientType: models.ClientTypeSecret,
		CredentialsSecretName: "my-app-oidc-credentials",
	}
	_, _, err := p.EnsureSecretClient(context.Background(), spec)
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestDeleteClientRefusesClientOwnedByAnotherCluster(t *testing.T) {
	p, admin := testProvider(t)
	admin.clientIDs["demo"] = map[string]string{"my-app": "existing-id"}
	admin.clientPayloads["existing-id"] = ClientPayload{Attributes: map[string]string{ClusterIDAttribute: "other-cluster"}}

	err := p.DeleteClient(context.Background(), "demo", "my-app")
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
	if admin.deleteClientCalls != 0 {
		t.Fatalf("expected DeleteClient not called, got %d", admin.deleteClientCalls)
	}
}

func TestEnsureSignedjwtClientSetsJwksAttributes(t *testing.T) {
	p, admin := testProvider(t)
	spec := &models.ClientSpec{
		Realm: "demo", ClientName: "my-app", ClientType: models.ClientTypeSignedJWT,
		CredentialsSecretName: "my-app-oidc-credentials",
	}

	clientID, err := p.EnsureSignedjwtClient(context.Background(), spec, `{"keys": []}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clientID != "my-app" {
		t.Fatalf("unexpected clientID: %q", clientID)
	}
	payload := admin.lastCreateClientPayload
	if payload.ClientAuthenticatorType != "client-jwt" {
		t.Fatalf("unexpected ClientAuthenticatorType: %q", payload.ClientAuthenticatorType)
	}
	if payload.Attributes["jwks.string"] != `{"keys": []}` || payload.Attributes["use.jwks.string"] != "true" {
		t.Fatalf("unexpected attributes: %+v", payload.Attributes)
	}
}

func TestEnsureSecretClientDemotesRealmDefaultScopesToOptional(t *testing.T) {
	p, admin := testProvider(t)
	spec := &models.ClientSpec{
		Realm: "demo", ClientName: "my-app", ClientType: models.ClientTypeSecret,
		CredentialsSecretName: "my-app-oidc-credentials",
	}

	// Real Keycloak automatically attaches the realm's default client scopes
	// (profile/roles/etc) to a freshly created client; the fake doesn't model
	// that on CreateClient, so seed it directly under the ID CreateClient is
	// about to generate ("internal-id-<clientID>", see fakeAdmin.CreateClient).
	admin.defaultScopes["internal-id-my-app"] = map[string]bool{"realm-default-scope-id": true}

	if _, _, err := p.EnsureSecretClient(context.Background(), spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.defaultScopes["internal-id-my-app"]["realm-default-scope-id"] {
		t.Fatalf("expected realm-default scope demoted off the default list, got %v", admin.defaultScopes)
	}
	if !admin.optionalScopes["internal-id-my-app"]["realm-default-scope-id"] {
		t.Fatalf("expected realm-default scope moved to optional, got %v", admin.optionalScopes)
	}
}

func TestDeleteClientNoopWhenAbsent(t *testing.T) {
	p, admin := testProvider(t)
	if err := p.DeleteClient(context.Background(), "demo", "my-app"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.deleteClientCalls != 0 {
		t.Fatalf("expected DeleteClient not called, got %d", admin.deleteClientCalls)
	}
}

func TestDeleteClientDeletesWhenPresent(t *testing.T) {
	p, admin := testProvider(t)
	admin.clientIDs["demo"] = map[string]string{"my-app": "existing-id"}
	admin.clientPayloads["existing-id"] = ClientPayload{Attributes: map[string]string{ClusterIDAttribute: "test-cluster"}}

	if err := p.DeleteClient(context.Background(), "demo", "my-app"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.deleteClientCalls != 1 {
		t.Fatalf("expected DeleteClient called once, got %d", admin.deleteClientCalls)
	}
}

func TestDeleteTenantNoopWhenAbsent(t *testing.T) {
	p, admin := testProvider(t)
	if err := p.DeleteTenant(context.Background(), "demo"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.deleteRealmCalls != 0 {
		t.Fatalf("expected DeleteRealm not called, got %d", admin.deleteRealmCalls)
	}
}

func TestDeleteTenantDeletesWhenPresent(t *testing.T) {
	p, admin := testProvider(t)
	admin.realms["demo"] = true
	admin.realmAttributes["demo"] = "test-cluster"

	if err := p.DeleteTenant(context.Background(), "demo"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin.deleteRealmCalls != 1 {
		t.Fatalf("expected DeleteRealm called once, got %d", admin.deleteRealmCalls)
	}
}

func TestIssuerURL(t *testing.T) {
	p, _ := testProvider(t)
	got, err := p.IssuerURL("demo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://kc.example.com/realms/demo" {
		t.Fatalf("unexpected issuer URL: %q", got)
	}
}

// GetOperatorToken is now a thin delegation to p.operatorAuth (a cache
// sharing the admin connection's own credential/source under a different
// scope) — see NewProvider and adminauth_test.go's
// TestAdminAuthAndOperatorAuthCacheIndependently for the scope-handling
// behavior itself.
func TestGetOperatorTokenDelegatesToOperatorAuth(t *testing.T) {
	p, _ := testProvider(t)
	token, err := p.GetOperatorToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "operator-token" {
		t.Fatalf("unexpected token: %q", token)
	}
}

func TestGetOperatorTokenSurfacesOperatorAuthError(t *testing.T) {
	p, _ := testProvider(t)
	p.operatorAuth = &fakeTokenProvider{err: errTest("boom")}
	if _, err := p.GetOperatorToken(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
