package auth0

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"myceliam/internal/models"
	"myceliam/internal/operr"
)

// fakeAuth0 is a minimal in-memory stand-in for the handful of Auth0
// Management API endpoints this package calls — enough to exercise the
// happy paths end to end without a live tenant; see this package's
// "TODO: verify against a live tenant" comments for what still needs
// confirming for real.
type fakeAuth0 struct {
	nextID   int
	apps     map[string]*auth0App // keyed by client_id
	servers  map[string]*resourceServer
	grants   map[string]*clientGrant // keyed by grant id
	actions  map[string]*auth0Action // keyed by action id
	bindings []string                // ordered action ids bound to credentials-exchange
	// activatedCreds tracks, per client_id, which credential ids were set via
	// a client_authentication_methods.private_key_jwt PATCH — mirrors what
	// EnsureSignedjwtClient's activation step does, kept separate from
	// auth0App itself since real Auth0 responses don't echo this shape back
	// on every GET the way client_metadata is.
	activatedCreds map[string][]string
	// credentials tracks, per client_id, its registered public_key
	// credentials — mirrors GET/POST /clients/{id}/credentials against a
	// real tenant closely enough to exercise findCredentialByName's
	// find-before-create path.
	credentials map[string][]credentialResponse
	// credentialCreateCalls counts every POST .../credentials across all
	// clients — used to assert findCredentialByName actually prevents a
	// second create attempt once one already exists (see
	// TestEnsureSignedjwtClientReusesExistingCredentialInsteadOfRecreating).
	credentialCreateCalls int
}

func newFakeAuth0() *fakeAuth0 {
	return &fakeAuth0{
		apps:           map[string]*auth0App{},
		servers:        map[string]*resourceServer{},
		grants:         map[string]*clientGrant{},
		actions:        map[string]*auth0Action{},
		activatedCreds: map[string][]string{},
		credentials:    map[string][]credentialResponse{},
	}
}

func (f *fakeAuth0) id() string {
	f.nextID++
	return strconv.Itoa(f.nextID)
}

func (f *fakeAuth0) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := strings.TrimPrefix(r.URL.Path, "/api/v2")

	switch {
	case r.Method == http.MethodGet && path == "/clients":
		out := []*auth0App{}
		for _, a := range f.apps {
			withoutSecret := *a
			withoutSecret.ClientSecret = ""
			out = append(out, &withoutSecret)
		}
		json.NewEncoder(w).Encode(out)

	case r.Method == http.MethodPost && path == "/clients":
		var app auth0App
		json.NewDecoder(r.Body).Decode(&app)
		app.ClientID = f.id()
		// Auth0 generates a client_secret for every non_interactive app at
		// creation regardless of intended auth method — private_key_jwt
		// activation happens separately via a later PATCH (see
		// EnsureSignedjwtClient), not at creation time.
		app.ClientSecret = "generated-secret-" + app.ClientID
		f.apps[app.ClientID] = &app
		json.NewEncoder(w).Encode(app)

	case r.Method == http.MethodGet && strings.HasPrefix(path, "/clients/") && !strings.Contains(path, "/credentials"):
		id := strings.SplitN(strings.TrimPrefix(path, "/clients/"), "?", 2)[0]
		if app, ok := f.apps[id]; ok {
			withoutSecret := *app
			withoutSecret.ClientSecret = ""
			json.NewEncoder(w).Encode(withoutSecret)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}

	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/clients/"):
		id := strings.TrimPrefix(path, "/clients/")
		// Merge-patch semantics, same as Auth0's real PATCH /clients/{id} —
		// only fields actually present in the request body get updated, so
		// e.g. EnsureSignedjwtClient's client_authentication_methods-only
		// activation PATCH doesn't wipe an app's existing client_metadata.
		var raw map[string]json.RawMessage
		json.NewDecoder(r.Body).Decode(&raw)
		app, ok := f.apps[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if v, present := raw["client_metadata"]; present {
			var md map[string]string
			json.Unmarshal(v, &md)
			app.ClientMetadata = md
		}
		if v, present := raw["client_authentication_methods"]; present {
			var methods struct {
				PrivateKeyJWT struct {
					Credentials []struct {
						ID string `json:"id"`
					} `json:"credentials"`
				} `json:"private_key_jwt"`
			}
			json.Unmarshal(v, &methods)
			var ids []string
			for _, c := range methods.PrivateKeyJWT.Credentials {
				ids = append(ids, c.ID)
			}
			f.activatedCreds[id] = ids
		}
		json.NewEncoder(w).Encode(app)

	case r.Method == http.MethodPost && strings.HasSuffix(path, "/credentials"):
		f.credentialCreateCalls++
		appID := strings.TrimSuffix(strings.TrimPrefix(path, "/clients/"), "/credentials")
		var body struct {
			Name string `json:"name"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		cred := credentialResponse{ID: f.id(), Kid: "fake-kid-" + f.id(), Name: body.Name}
		f.credentials[appID] = append(f.credentials[appID], cred)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(cred)

	case r.Method == http.MethodGet && strings.HasSuffix(path, "/credentials"):
		appID := strings.TrimSuffix(strings.TrimPrefix(path, "/clients/"), "/credentials")
		out := f.credentials[appID]
		if out == nil {
			out = []credentialResponse{}
		}
		json.NewEncoder(w).Encode(out)

	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/clients/"):
		delete(f.apps, strings.TrimPrefix(path, "/clients/"))
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && path == "/resource-servers":
		out := []*resourceServer{}
		for _, s := range f.servers {
			out = append(out, s)
		}
		json.NewEncoder(w).Encode(out)

	case r.Method == http.MethodPost && path == "/resource-servers":
		var rs resourceServer
		json.NewDecoder(r.Body).Decode(&rs)
		rs.ID = f.id()
		f.servers[rs.ID] = &rs
		json.NewEncoder(w).Encode(rs)

	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/resource-servers/"):
		delete(f.servers, strings.TrimPrefix(path, "/resource-servers/"))
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && strings.HasPrefix(path, "/client-grants"):
		audience := r.URL.Query().Get("audience")
		out := []*clientGrant{}
		for _, g := range f.grants {
			if g.Audience == audience {
				out = append(out, g)
			}
		}
		json.NewEncoder(w).Encode(out)

	case r.Method == http.MethodPost && path == "/client-grants":
		var g clientGrant
		json.NewDecoder(r.Body).Decode(&g)
		g.ID = f.id()
		f.grants[g.ID] = &g
		json.NewEncoder(w).Encode(g)

	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/client-grants/"):
		delete(f.grants, strings.TrimPrefix(path, "/client-grants/"))
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPost && path == "/oauth/token":
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-management-token",
			"expires_in":   86400,
			"token_type":   "Bearer",
		})

	case r.Method == http.MethodGet && path == "/actions/actions":
		out := []*auth0Action{}
		for _, a := range f.actions {
			out = append(out, a)
		}
		json.NewEncoder(w).Encode(map[string]any{"actions": out})

	case r.Method == http.MethodPost && path == "/actions/actions":
		var a auth0Action
		json.NewDecoder(r.Body).Decode(&a)
		a.ID = f.id()
		f.actions[a.ID] = &a
		json.NewEncoder(w).Encode(a)

	case r.Method == http.MethodGet && strings.HasPrefix(path, "/actions/actions/"):
		id := strings.TrimPrefix(path, "/actions/actions/")
		if a, ok := f.actions[id]; ok {
			json.NewEncoder(w).Encode(a)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}

	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/actions/actions/"):
		id := strings.TrimPrefix(path, "/actions/actions/")
		var body struct {
			Code string `json:"code"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if a, ok := f.actions[id]; ok {
			a.Code = body.Code
			json.NewEncoder(w).Encode(a)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}

	case r.Method == http.MethodPost && strings.HasSuffix(path, "/deploy"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/actions/actions/"), "/deploy")
		if a, ok := f.actions[id]; ok {
			a.AllChangesDeployed = true
		}
		w.WriteHeader(http.StatusOK)

	case r.Method == http.MethodGet && path == "/actions/triggers/"+credentialsExchangeTrigger+"/bindings":
		type bindingEntry struct {
			Action auth0Action `json:"action"`
		}
		out := make([]bindingEntry, 0, len(f.bindings))
		for _, id := range f.bindings {
			out = append(out, bindingEntry{Action: *f.actions[id]})
		}
		json.NewEncoder(w).Encode(map[string]any{"bindings": out})

	case r.Method == http.MethodPatch && path == "/actions/triggers/"+credentialsExchangeTrigger+"/bindings":
		var body struct {
			Bindings []actionBinding `json:"bindings"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		// Auth0 rejects binding an Action that hasn't been deployed yet —
		// mirrored here so TestEnsureTenantDeploysActionThatExistsButWasNeverDeployed
		// gets a realistic 400 if the fix under test doesn't deploy first.
		for _, b := range body.Bindings {
			if a, ok := f.actions[b.Ref.Value]; ok && !a.AllChangesDeployed {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"message": "Trying to create a binding for an action that has not been deployed yet."})
				return
			}
		}
		f.bindings = f.bindings[:0]
		for _, b := range body.Bindings {
			f.bindings = append(f.bindings, b.Ref.Value)
		}
		w.WriteHeader(http.StatusOK)

	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"error":"no fake handler for %s %s"}`, r.Method, path)
	}
}

func testProvider(t *testing.T, serverURL string) *Provider {
	t.Helper()
	s := testSettings(t, nil)
	c := fakeClientWithObjects(t, opaqueSecret(s.SystemNamespace, AdminSecretName, "shh"))
	p, err := New(context.Background(), s, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// New() builds baseURL as "https://{Settings.Auth0Domain}" — point both
	// the Provider and its token source at the fake (plain-http) server
	// instead.
	p.baseURL = serverURL
	p.auth.source.(*secretSource).domain = serverURL
	return p
}

func testSpec(clientType models.ClientType) *models.ClientSpec {
	return &models.ClientSpec{
		Realm: "test-cluster-demo", ClientName: "my-app", ClientType: clientType, CredentialsSecretName: "x",
	}
}

func TestEnsureTenantCreatesDeploysAndBindsActionOnce(t *testing.T) {
	fake := newFakeAuth0()
	server := httptest.NewServer(fake)
	defer server.Close()
	p := testProvider(t, server.URL)

	if err := p.EnsureTenant(context.Background(), "demo"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.actions) != 1 {
		t.Fatalf("expected 1 Action created, got %d", len(fake.actions))
	}
	if len(fake.bindings) != 1 {
		t.Fatalf("expected 1 binding to credentials-exchange, got %v", fake.bindings)
	}

	// A second call (a second SA's reconcile, in practice) must not create a
	// duplicate Action or re-bind it — cached after the first success.
	if err := p.EnsureTenant(context.Background(), "other-ns"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.actions) != 1 {
		t.Fatalf("expected still only 1 Action after a second EnsureTenant, got %d", len(fake.actions))
	}
}

// TestActionScriptProjectsAwsSessionTags guards the AWS session-tags
// mechanism confirmed live this session (see actionScript's own doc
// comment): each of the four myceliam_* claims must also land in
// "https://aws.amazon.com/tags".principal_tags as a single-element array —
// AWS rejects the whole token outright if any array there ever has more
// than one entry, so this is a real, easy-to-break invariant, not just a
// style preference.
func TestActionScriptProjectsAwsSessionTags(t *testing.T) {
	if !strings.Contains(actionScript, "https://aws.amazon.com/tags") {
		t.Fatal("expected actionScript to set the https://aws.amazon.com/tags claim")
	}
	if !strings.Contains(actionScript, "principal_tags") {
		t.Fatal("expected actionScript to nest tags under principal_tags")
	}
	if !strings.Contains(actionScript, "[md[key]]") {
		t.Fatal("expected actionScript to wrap each principal tag value in a single-element array")
	}
}

func TestEnsureTenantUpdatesStaleActionCode(t *testing.T) {
	fake := newFakeAuth0()
	// Simulate a tenant already provisioned by an older myceliam build,
	// before claim names were simplified — EnsureTenant must bring this up
	// to date rather than treating "an Action with this name exists" as
	// good enough on its own.
	fake.actions["stale"] = &auth0Action{ID: "stale", Name: actionName, Code: "exports.onExecuteCredentialsExchange = async () => {};"}
	fake.bindings = []string{"stale"}
	server := httptest.NewServer(fake)
	defer server.Close()
	p := testProvider(t, server.URL)

	if err := p.EnsureTenant(context.Background(), "demo"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.actions) != 1 {
		t.Fatalf("expected no new Action created, got %d", len(fake.actions))
	}
	if fake.actions["stale"].Code != actionScript {
		t.Fatalf("expected stale Action's code to be updated to actionScript, got %q", fake.actions["stale"].Code)
	}
}

// TestEnsureTenantDeploysActionThatExistsButWasNeverDeployed guards against
// a real bug confirmed live: an Action found with code already matching
// actionScript (so ensureActionCodeCurrent's content check alone says
// "nothing to do") but never actually deployed — e.g. created manually, or
// left mid-provisioning by an earlier failed run — must still be deployed
// before ensureActionBound tries to bind it, or Auth0 rejects the binding
// with "Trying to create a binding for an action that has not been deployed
// yet." Previously ensureActionCodeCurrent only checked Code equality and
// silently skipped deployment in this exact state.
func TestEnsureTenantDeploysActionThatExistsButWasNeverDeployed(t *testing.T) {
	fake := newFakeAuth0()
	fake.actions["undeployed"] = &auth0Action{ID: "undeployed", Name: actionName, Code: actionScript, AllChangesDeployed: false}
	server := httptest.NewServer(fake)
	defer server.Close()
	p := testProvider(t, server.URL)

	if err := p.EnsureTenant(context.Background(), "demo"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fake.actions["undeployed"].AllChangesDeployed {
		t.Fatal("expected the pre-existing, never-deployed Action to be deployed")
	}
	if len(fake.bindings) != 1 || fake.bindings[0] != "undeployed" {
		t.Fatalf("expected the Action bound to credentials-exchange after deploying, got %v", fake.bindings)
	}
}

func TestEnsureTenantPreservesOtherBindingsOnSameTrigger(t *testing.T) {
	fake := newFakeAuth0()
	// Simulate an admin having already bound an unrelated Action to
	// credentials-exchange before myceliam ever ran.
	fake.actions["existing"] = &auth0Action{ID: "existing", Name: "some-other-action", AllChangesDeployed: true}
	fake.bindings = []string{"existing"}
	server := httptest.NewServer(fake)
	defer server.Close()
	p := testProvider(t, server.URL)

	if err := p.EnsureTenant(context.Background(), "demo"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.bindings) != 2 || fake.bindings[0] != "existing" {
		t.Fatalf("expected myceliam's Action appended, not replacing the existing binding, got %v", fake.bindings)
	}
}

// TestDeleteTenantIsNoop covers the case where neither namespace-scoped
// Resource Server ever existed — the common case for a tenantID with no aws
// or gcp cloud federation ever configured.
func TestDeleteTenantIsNoop(t *testing.T) {
	server := httptest.NewServer(newFakeAuth0())
	defer server.Close()
	p := testProvider(t, server.URL)

	if err := p.DeleteTenant(context.Background(), "demo"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDeleteTenantForceDeletesNamespaceScopedResourceServers guards a real
// bug found live: with no namespace-teardown-time fallback, an Auth0
// Resource Server ("aws-test-cluster-demo" in the actual live case this
// guards) survived a ServiceAccount/namespace deletion — unlike Keycloak's
// realm, which always gets wholesale-deleted regardless of any individual
// client's own cleanup history. DeleteTenant must force-delete both
// namespace-scoped Resource Servers (and any Client Grants against them)
// outright, not rely on DeleteAccessScope's own last-one-out cleanup having
// already run for every referencing SA.
func TestDeleteTenantForceDeletesNamespaceScopedResourceServers(t *testing.T) {
	server := httptest.NewServer(newFakeAuth0())
	defer server.Close()
	p := testProvider(t, server.URL)

	if _, _, err := p.EnsureSecretClient(context.Background(), testSpec(models.ClientTypeSecret)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	awsAudience := "aws-test-cluster-demo"
	if _, err := p.EnsureAccessScope(context.Background(), "test-cluster-demo", "my-app", awsAudience, awsAudience); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, found, err := p.findResourceServerByAudience(context.Background(), awsAudience); err != nil || !found {
		t.Fatalf("expected resource server to exist before DeleteTenant, found=%v err=%v", found, err)
	}

	if err := p.DeleteTenant(context.Background(), "test-cluster-demo"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, found, err := p.findResourceServerByAudience(context.Background(), awsAudience); err != nil || found {
		t.Fatalf("expected resource server to be gone after DeleteTenant, found=%v err=%v", found, err)
	}
	var remaining []clientGrant
	if err := p.doRequest(context.Background(), "GET", "/client-grants?audience="+awsAudience, nil, &remaining); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected no client grants to remain, got %+v", remaining)
	}
}

func TestEnsureSignedjwtClientReturnsAuth0AssignedKidNotHint(t *testing.T) {
	fake := newFakeAuth0()
	server := httptest.NewServer(fake)
	defer server.Close()
	p := testProvider(t, server.URL)

	// This is the actual bug this whole change fixes: Auth0 computes its own
	// kid independently (per the JWK Thumbprint standard) regardless of what
	// the caller hints — the fake server's /credentials handler returns a
	// distinct "fake-kid-N" unrelated to the hint, exactly modeling that.
	clientID, actualKid, err := p.EnsureSignedjwtClient(context.Background(), testSpec(models.ClientTypeSignedJWT), []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"), `{"keys":[]}`, "hint-kid-should-be-ignored")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clientID == "" {
		t.Fatal("expected non-empty clientID")
	}
	if actualKid == "" || actualKid == "hint-kid-should-be-ignored" {
		t.Fatalf("expected actualKid to come from Auth0's own response, not the hint, got %q", actualKid)
	}
	// Guards the activation step this fix adds: registering the credential
	// alone doesn't enable private_key_jwt auth — confirmed live against a
	// real tenant that this requires a separate PATCH setting
	// client_authentication_methods.private_key_jwt.credentials.
	if len(fake.activatedCreds[clientID]) != 1 {
		t.Fatalf("expected exactly 1 credential activated via client_authentication_methods, got %v", fake.activatedCreds[clientID])
	}
}

// TestEnsureSignedjwtClientReusesExistingCredentialInsteadOfRecreating guards
// a real bug confirmed live against a free/dev Auth0 tenant: Client
// Credentials (public_key/private_key_jwt) have a hard cap that's TENANT-WIDE
// (2 total across every Application, in the tenant this was found in), not
// per-client. Without a find-before-create check, a reconcile that succeeds
// at registering the credential but fails before/during the activation PATCH
// (e.g. the operator's cached Management API token was minted before an
// admin granted update:client_credentials) gets stuck forever: every retry
// re-POSTs a brand new credential, which permanently fails with
// "too_many_entities" once the tenant is at its cap, and the one credential
// that already succeeded never gets activated. This asserts a second
// EnsureSignedjwtClient call reuses the existing credential (by name) rather
// than attempting to create another.
func TestEnsureSignedjwtClientReusesExistingCredentialInsteadOfRecreating(t *testing.T) {
	fake := newFakeAuth0()
	server := httptest.NewServer(fake)
	defer server.Close()
	p := testProvider(t, server.URL)
	spec := testSpec(models.ClientTypeSignedJWT)
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")

	clientID, firstKid, err := p.EnsureSignedjwtClient(context.Background(), spec, certPEM, `{"keys":[]}`, "hint")
	if err != nil {
		t.Fatalf("unexpected error on first call: %v", err)
	}
	if fake.credentialCreateCalls != 1 {
		t.Fatalf("expected exactly 1 credential creation after the first call, got %d", fake.credentialCreateCalls)
	}

	// Simulate a prior run's activation having failed/never happened (e.g.
	// insufficient scope at the time) despite the credential already
	// existing — the exact live-observed state this fix recovers from.
	fake.activatedCreds[clientID] = nil

	_, secondKid, err := p.EnsureSignedjwtClient(context.Background(), spec, certPEM, `{"keys":[]}`, "hint")
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if fake.credentialCreateCalls != 1 {
		t.Fatalf("expected the second call to reuse the existing credential, not create another — got %d create calls", fake.credentialCreateCalls)
	}
	if secondKid != firstKid {
		t.Fatalf("expected the reused credential's kid to stay %q, got %q", firstKid, secondKid)
	}
	if len(fake.activatedCreds[clientID]) != 1 {
		t.Fatal("expected the second call to (re-)activate the existing credential")
	}
}

func TestIssuerURLIgnoresTenant(t *testing.T) {
	server := httptest.NewServer(newFakeAuth0())
	defer server.Close()
	p := testProvider(t, server.URL)

	issuer, err := p.IssuerURL("anything")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if issuer != p.baseURL+"/" {
		t.Fatalf("unexpected issuer: %q", issuer)
	}
	issuer2, err := p.IssuerURL("something-else")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if issuer2 != issuer {
		t.Fatalf("expected issuer to be identical regardless of tenantID, got %q vs %q", issuer, issuer2)
	}
}

func TestEnsureSecretClientSetsBaseMetadata(t *testing.T) {
	server := httptest.NewServer(newFakeAuth0())
	defer server.Close()
	p := testProvider(t, server.URL)

	clientID, clientSecret, err := p.EnsureSecretClient(context.Background(), testSpec(models.ClientTypeSecret))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clientID == "" || clientSecret == "" {
		t.Fatalf("expected non-empty clientID/clientSecret, got %q/%q", clientID, clientSecret)
	}
	app := p.mustFindApp(t, "my-app")
	if app.ClientMetadata["cluster_id"] != "test-cluster" || app.ClientMetadata["namespace"] != "demo" || app.ClientMetadata["service_account"] != "my-app" {
		t.Fatalf("unexpected client_metadata: %+v", app.ClientMetadata)
	}
}

func (p *Provider) mustFindApp(t *testing.T, name string) *auth0App {
	t.Helper()
	app, found, err := p.findAppByName(context.Background(), name)
	if err != nil || !found {
		t.Fatalf("expected to find app %q, found=%v err=%v", name, found, err)
	}
	return app
}

func TestEnsureSecretClientIsIdempotent(t *testing.T) {
	server := httptest.NewServer(newFakeAuth0())
	defer server.Close()
	p := testProvider(t, server.URL)

	if _, _, err := p.EnsureSecretClient(context.Background(), testSpec(models.ClientTypeSecret)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Second call finds the existing app rather than creating a duplicate —
	// and correctly reports the secret is no longer retrievable, since Auth0
	// only returns it once.
	if _, _, err := p.EnsureSecretClient(context.Background(), testSpec(models.ClientTypeSecret)); err == nil {
		t.Fatal("expected an error on re-ensuring an already-created secret client (Auth0 never re-returns a secret)")
	}
}

func TestEnsureAccessScopeCreatesResourceServerGrantsClientAndAccumulatesCloud(t *testing.T) {
	server := httptest.NewServer(newFakeAuth0())
	defer server.Close()
	p := testProvider(t, server.URL)

	clientID, _, err := p.EnsureSecretClient(context.Background(), testSpec(models.ClientTypeSecret))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// EnsureAccessScope's third argument is the ServiceAccount's own name
	// (clientName), not Auth0's assigned clientID — reconcile.go only ever
	// has the former on hand; resolveClientID translates it internally.
	awsAudience := "aws-test-cluster-demo"
	azpValue, err := p.EnsureAccessScope(context.Background(), "test-cluster-demo", "my-app", awsAudience, awsAudience)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// azpValue must be Auth0's own assigned clientID, not the SA name
	// ("my-app") passed in as clientName — Auth0's azp claim carries its own
	// opaque client_id, unlike Keycloak where it'd just echo clientName.
	if azpValue != clientID {
		t.Fatalf("expected azpValue to be Auth0's clientID %q, got %q", clientID, azpValue)
	}
	app := p.mustFindApp(t, "my-app")
	if app.ClientMetadata["cloud"] != "aws" {
		t.Fatalf("expected cloud=aws after first EnsureAccessScope, got %q", app.ClientMetadata["cloud"])
	}

	gcpAudience := "gcp-test-cluster-demo"
	if _, err := p.EnsureAccessScope(context.Background(), "test-cluster-demo", "my-app", gcpAudience, gcpAudience); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	app = p.mustFindApp(t, "my-app")
	if app.ClientMetadata["cloud"] != "aws,gcp" {
		t.Fatalf("expected cloud=aws,gcp after second EnsureAccessScope, got %q", app.ClientMetadata["cloud"])
	}

	// Idempotent: re-ensuring the same cloud must not duplicate it.
	if _, err := p.EnsureAccessScope(context.Background(), "test-cluster-demo", "my-app", awsAudience, awsAudience); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	app = p.mustFindApp(t, "my-app")
	if app.ClientMetadata["cloud"] != "aws,gcp" {
		t.Fatalf("expected cloud to stay 'aws,gcp' after re-ensuring aws, got %q", app.ClientMetadata["cloud"])
	}

	grant, found, err := p.findClientGrant(context.Background(), clientID, awsAudience)
	if err != nil || !found {
		t.Fatalf("expected a client grant for aws, found=%v err=%v", found, err)
	}
	if grant.ClientID != clientID {
		t.Fatalf("unexpected grant client_id: %+v", grant)
	}
}

// TestEnsureAccessScopeResolvesClientNameNotRawClientID guards a real bug
// confirmed live: reconcile.go's reconcileCloud calls EnsureAccessScope with
// the ServiceAccount's own Kubernetes name (e.g. "auth0-jwt"), never Auth0's
// own opaque client_id — correct for Keycloak, where client_id IS the
// SA name by construction, but Auth0 assigns a random one instead. Passing
// the SA name straight through to POST /client-grants 404s with "Client not
// found" (errorCode inexistent_client). This asserts the grant actually
// lands on the real, Auth0-assigned client_id, not the name string.
func TestEnsureAccessScopeResolvesClientNameNotRawClientID(t *testing.T) {
	server := httptest.NewServer(newFakeAuth0())
	defer server.Close()
	p := testProvider(t, server.URL)

	realClientID, _, err := p.EnsureSecretClient(context.Background(), testSpec(models.ClientTypeSecret))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	audience := "aws-test-cluster-demo"
	// "my-app" is spec.ClientName (the SA name) — exactly what reconcile.go
	// actually has on hand, never the real client_id.
	if _, err := p.EnsureAccessScope(context.Background(), "test-cluster-demo", "my-app", audience, audience); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grant, found, err := p.findClientGrant(context.Background(), realClientID, audience)
	if err != nil || !found {
		t.Fatalf("expected a client grant on the real client_id %q, found=%v err=%v", realClientID, found, err)
	}
	if grant.ClientID != realClientID {
		t.Fatalf("expected grant.ClientID to be the real client_id %q, got %q", realClientID, grant.ClientID)
	}
}

// TestEnsureAccessScopeRetriesWhenAppNotYetCreated guards resolveClientID's
// new retry behavior: EnsureAccessScope can legitimately run before
// reconcileClient has created the Application (reconcile ordering isn't
// guaranteed), so a not-found Application must produce an *operr.Temporary,
// not a hard/permanent failure.
func TestEnsureAccessScopeRetriesWhenAppNotYetCreated(t *testing.T) {
	server := httptest.NewServer(newFakeAuth0())
	defer server.Close()
	p := testProvider(t, server.URL)

	_, err := p.EnsureAccessScope(context.Background(), "test-cluster-demo", "never-created-app", "aws-test-cluster-demo", "aws-test-cluster-demo")
	if _, ok := operr.AsTemporary(err); !ok {
		t.Fatalf("expected *operr.Temporary for a not-yet-created Application, got %v", err)
	}
}

func TestDeleteAccessScopeRemovesGrantCloudAndDeletesResourceServerWhenEmpty(t *testing.T) {
	server := httptest.NewServer(newFakeAuth0())
	defer server.Close()
	p := testProvider(t, server.URL)

	if _, _, err := p.EnsureSecretClient(context.Background(), testSpec(models.ClientTypeSecret)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	audience := "aws-test-cluster-demo"
	if _, err := p.EnsureAccessScope(context.Background(), "test-cluster-demo", "my-app", audience, audience); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := p.DeleteAccessScope(context.Background(), "test-cluster-demo", "my-app", audience); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, found, err := p.findResourceServerByAudience(context.Background(), audience); err != nil || found {
		t.Fatalf("expected Resource Server to be deleted once its last grant is removed, found=%v err=%v", found, err)
	}
	app := p.mustFindApp(t, "my-app")
	if app.ClientMetadata["cloud"] != "" {
		t.Fatalf("expected cloud metadata cleared, got %q", app.ClientMetadata["cloud"])
	}
}

func TestDeleteClientDeletesApp(t *testing.T) {
	server := httptest.NewServer(newFakeAuth0())
	defer server.Close()
	p := testProvider(t, server.URL)

	if _, _, err := p.EnsureSecretClient(context.Background(), testSpec(models.ClientTypeSecret)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := p.DeleteClient(context.Background(), "test-cluster-demo", "my-app"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, found, err := p.findAppByName(context.Background(), "my-app"); err != nil || found {
		t.Fatalf("expected app to be deleted, found=%v err=%v", found, err)
	}
}

func TestDeleteClientNoopWhenAbsent(t *testing.T) {
	server := httptest.NewServer(newFakeAuth0())
	defer server.Close()
	p := testProvider(t, server.URL)

	if err := p.DeleteClient(context.Background(), "test-cluster-demo", "never-existed"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetOperatorTokenFailsWithoutAudienceConfigured(t *testing.T) {
	server := httptest.NewServer(newFakeAuth0())
	defer server.Close()
	p := testProvider(t, server.URL)

	if _, err := p.GetOperatorToken(context.Background()); err == nil {
		t.Fatal("expected error from GetOperatorToken with no Auth0OperatorAudience configured")
	}
}

func TestGetOperatorTokenProvisionsResourceServerGrantAndFetchesToken(t *testing.T) {
	fake := newFakeAuth0()
	server := httptest.NewServer(fake)
	defer server.Close()

	s := testSettings(t, map[string]string{"AUTH0_OPERATOR_AUDIENCE": "aws-operator-bootstrap"})
	c := fakeClientWithObjects(t, opaqueSecret(s.SystemNamespace, AdminSecretName, "shh"))
	p, err := New(context.Background(), s, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p.baseURL = server.URL
	p.auth.source.(*secretSource).domain = server.URL

	token, err := p.GetOperatorToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" {
		t.Fatal("expected a non-empty token")
	}

	if _, found, err := p.findResourceServerByAudience(context.Background(), "aws-operator-bootstrap"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	} else if !found {
		t.Fatal("expected ensureOperatorAccessScope to have created the Resource Server")
	}
	if _, found, err := p.findClientGrant(context.Background(), s.Auth0OperatorClientID, "aws-operator-bootstrap"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	} else if !found {
		t.Fatal("expected ensureOperatorAccessScope to have created the Client Grant")
	}

	// Calling again must not create a second Resource Server or grant —
	// operatorScopeEnsured should short-circuit provisioning on repeat calls.
	if _, err := p.GetOperatorToken(context.Background()); err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if len(fake.servers) != 1 {
		t.Fatalf("expected exactly 1 resource server, got %d", len(fake.servers))
	}
	if len(fake.grants) != 1 {
		t.Fatalf("expected exactly 1 client grant, got %d", len(fake.grants))
	}
}
