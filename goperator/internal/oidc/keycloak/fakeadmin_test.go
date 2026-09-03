package keycloak

import "context"

// fakeAdmin is an in-memory AdminAPI test double — the Go equivalent of the
// Python suite's mocker.patch(KeycloakAdmin)/MagicMock fixture. Each method
// consults an optional func field first (for tests that need to simulate a
// specific error/race), falling back to simple in-memory state otherwise.
type fakeAdmin struct {
	realms map[string]bool
	// realm -> its stamped myceliam.io/cluster-id value, if any
	realmAttributes map[string]string

	// realm -> clientName -> internal id
	clientIDs map[string]map[string]string
	// internal id -> payload
	clientPayloads map[string]ClientPayload
	// internal id -> secret ("", false if none generated yet)
	clientSecrets map[string]string

	// realm -> scopeName -> id
	scopeIDs map[string]map[string]string
	// clientID -> set of attached scope IDs
	optionalScopes map[string]map[string]bool
	defaultScopes  map[string]map[string]bool
	// scopeID -> its audience mapper's current value
	scopeAudiences map[string]string

	nextID int

	// Call recording, used by tests that assert "not called" / "called once".
	createClientCalls       int
	updateClientCalls       int
	deleteClientCalls       int
	createRealmCalls        int
	deleteRealmCalls        int
	generateSecretCalls     int
	createScopeCalls        int
	attachScopeCalls        int
	deleteScopeCalls        int
	detachDefaultScopeCalls int
	lastCreateClientPayload ClientPayload
	lastUpdateClientPayload ClientPayload

	// Error injection hooks.
	realmExistsErr               error
	createRealmErr               error
	findClientErr                error
	createClientErr              error
	clientSecretErr              error
	generateClientSecretErr      error
	findClientScopeErr           error
	createClientScopeErr         error
	clientOptionalScopeIDsErr    error
	attachOptionalScopeErr       error
	clientDefaultScopeIDsErr     error
	detachDefaultScopeErr        error
	ensureClientScopeAudienceErr error
}

func newFakeAdmin() *fakeAdmin {
	return &fakeAdmin{
		realms:          map[string]bool{},
		realmAttributes: map[string]string{},
		clientIDs:       map[string]map[string]string{},
		clientPayloads:  map[string]ClientPayload{},
		clientSecrets:   map[string]string{},
		scopeIDs:        map[string]map[string]string{},
		optionalScopes:  map[string]map[string]bool{},
		defaultScopes:   map[string]map[string]bool{},
		scopeAudiences:  map[string]string{},
	}
}

func (f *fakeAdmin) genID(prefix string) string {
	f.nextID++
	return prefix
}

func (f *fakeAdmin) RealmExists(ctx context.Context, token, realm string) (bool, map[string]string, error) {
	if f.realmExistsErr != nil {
		return false, nil, f.realmExistsErr
	}
	if !f.realms[realm] {
		return false, nil, nil
	}
	var attrs map[string]string
	if clusterID, ok := f.realmAttributes[realm]; ok {
		attrs = map[string]string{ClusterIDAttribute: clusterID}
	}
	return true, attrs, nil
}

func (f *fakeAdmin) CreateRealm(ctx context.Context, token, realm, clusterID string) error {
	f.createRealmCalls++
	if f.createRealmErr != nil {
		return f.createRealmErr
	}
	f.realms[realm] = true
	f.realmAttributes[realm] = clusterID
	return nil
}

func (f *fakeAdmin) DeleteRealm(ctx context.Context, token, realm string) error {
	f.deleteRealmCalls++
	delete(f.realms, realm)
	return nil
}

func (f *fakeAdmin) FindClient(ctx context.Context, token, realm, clientName string) (string, map[string]string, bool, error) {
	if f.findClientErr != nil {
		return "", nil, false, f.findClientErr
	}
	byName, ok := f.clientIDs[realm]
	if !ok {
		return "", nil, false, nil
	}
	id, ok := byName[clientName]
	if !ok {
		return "", nil, false, nil
	}
	return id, f.clientPayloads[id].Attributes, true, nil
}

func (f *fakeAdmin) CreateClient(ctx context.Context, token, realm string, payload ClientPayload) (string, error) {
	f.createClientCalls++
	f.lastCreateClientPayload = payload
	if f.createClientErr != nil {
		return "", f.createClientErr
	}
	id := "internal-id-" + payload.ClientID
	if _, ok := f.clientIDs[realm]; !ok {
		f.clientIDs[realm] = map[string]string{}
	}
	f.clientIDs[realm][payload.ClientID] = id
	f.clientPayloads[id] = payload
	return id, nil
}

func (f *fakeAdmin) UpdateClient(ctx context.Context, token, realm, id string, payload ClientPayload) error {
	f.updateClientCalls++
	f.lastUpdateClientPayload = payload
	f.clientPayloads[id] = payload
	return nil
}

func (f *fakeAdmin) DeleteClient(ctx context.Context, token, realm, id string) error {
	f.deleteClientCalls++
	delete(f.clientPayloads, id)
	for name, cid := range f.clientIDs[realm] {
		if cid == id {
			delete(f.clientIDs[realm], name)
		}
	}
	return nil
}

func (f *fakeAdmin) ClientSecret(ctx context.Context, token, realm, id string) (string, bool, error) {
	if f.clientSecretErr != nil {
		return "", false, f.clientSecretErr
	}
	secret, ok := f.clientSecrets[id]
	return secret, ok && secret != "", nil
}

func (f *fakeAdmin) GenerateClientSecret(ctx context.Context, token, realm, id string) (string, error) {
	f.generateSecretCalls++
	if f.generateClientSecretErr != nil {
		return "", f.generateClientSecretErr
	}
	secret := "generated-secret"
	f.clientSecrets[id] = secret
	return secret, nil
}

func (f *fakeAdmin) FindClientScope(ctx context.Context, token, realm, scopeName string) (string, bool, error) {
	if f.findClientScopeErr != nil {
		return "", false, f.findClientScopeErr
	}
	byName, ok := f.scopeIDs[realm]
	if !ok {
		return "", false, nil
	}
	id, ok := byName[scopeName]
	return id, ok, nil
}

func (f *fakeAdmin) CreateClientScopeWithAudienceMapper(ctx context.Context, token, realm, scopeName, audience string) (string, error) {
	f.createScopeCalls++
	if f.createClientScopeErr != nil {
		return "", f.createClientScopeErr
	}
	id := "scope-id-" + scopeName
	if _, ok := f.scopeIDs[realm]; !ok {
		f.scopeIDs[realm] = map[string]string{}
	}
	f.scopeIDs[realm][scopeName] = id
	f.scopeAudiences[id] = audience
	return id, nil
}

func (f *fakeAdmin) EnsureClientScopeAudience(ctx context.Context, token, realm, scopeID, audience string) error {
	if f.ensureClientScopeAudienceErr != nil {
		return f.ensureClientScopeAudienceErr
	}
	f.scopeAudiences[scopeID] = audience
	return nil
}

func (f *fakeAdmin) DeleteClientScope(ctx context.Context, token, realm, scopeID string) error {
	f.deleteScopeCalls++
	for name, id := range f.scopeIDs[realm] {
		if id == scopeID {
			delete(f.scopeIDs[realm], name)
		}
	}
	return nil
}

func (f *fakeAdmin) ClientOptionalScopeIDs(ctx context.Context, token, realm, clientID string) ([]string, error) {
	if f.clientOptionalScopeIDsErr != nil {
		return nil, f.clientOptionalScopeIDsErr
	}
	var ids []string
	for id := range f.optionalScopes[clientID] {
		ids = append(ids, id)
	}
	return ids, nil
}

func (f *fakeAdmin) AttachOptionalScope(ctx context.Context, token, realm, clientID, scopeID string) error {
	f.attachScopeCalls++
	if f.attachOptionalScopeErr != nil {
		return f.attachOptionalScopeErr
	}
	if _, ok := f.optionalScopes[clientID]; !ok {
		f.optionalScopes[clientID] = map[string]bool{}
	}
	f.optionalScopes[clientID][scopeID] = true
	return nil
}

func (f *fakeAdmin) ClientDefaultScopeIDs(ctx context.Context, token, realm, clientID string) ([]string, error) {
	if f.clientDefaultScopeIDsErr != nil {
		return nil, f.clientDefaultScopeIDsErr
	}
	var ids []string
	for id := range f.defaultScopes[clientID] {
		ids = append(ids, id)
	}
	return ids, nil
}

func (f *fakeAdmin) DetachDefaultScope(ctx context.Context, token, realm, clientID, scopeID string) error {
	f.detachDefaultScopeCalls++
	if f.detachDefaultScopeErr != nil {
		return f.detachDefaultScopeErr
	}
	delete(f.defaultScopes[clientID], scopeID)
	return nil
}

// fakeTokenProvider is a tokenProvider test double returning a fixed token.
type fakeTokenProvider struct {
	token string
	err   error
}

func (f *fakeTokenProvider) Token(ctx context.Context) (string, error) {
	return f.token, f.err
}
