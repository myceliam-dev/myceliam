package keycloak

import "context"

// ClusterIDAttribute is the Keycloak realm/client attribute key myceliam
// stamps at creation and checks on every subsequent reconcile, mirroring
// ArgoCD's own resource-tracking labels: it names which cluster (per
// config.Settings.ClusterID) created this realm/client, so a differently-
// configured cluster that somehow collides on the same name (e.g. a
// duplicate ClusterID, or manual tampering) gets refused rather than
// silently allowed to adopt or overwrite it.
const ClusterIDAttribute = "myceliam.io/cluster-id"

// ClientPayload is the subset of a Keycloak client representation
// KeycloakProvider needs to create/update, independent of gocloak's own
// pointer-heavy Client struct.
type ClientPayload struct {
	ClientID                  string
	Enabled                   bool
	Protocol                  string
	PublicClient              bool
	ServiceAccountsEnabled    bool
	StandardFlowEnabled       bool
	DirectAccessGrantsEnabled bool
	ClientAuthenticatorType   string
	Attributes                map[string]string
}

// AdminAPI is the subset of the Keycloak Admin REST API KeycloakProvider
// needs — the seam that lets tests inject a fake instead of a live server,
// the Go equivalent of the Python test suite's mocker.patch(KeycloakAdmin).
// gocloakAdmin (adminapi_gocloak.go) is the real implementation, backed by
// github.com/Nerzal/gocloak/v13.
//
// Every method takes realm explicitly (mirroring gocloak's own per-call realm
// parameter) rather than a stateful "current realm" — unlike python-keycloak's
// KeycloakAdmin, which mutates a single shared connection.realm_name field
// (see client.py's _for_realm/_realm_lock), there is no shared mutable realm
// state here for concurrent reconciles to race on, so no equivalent lock is
// needed anywhere in this package.
type AdminAPI interface {
	// RealmExists also surfaces the realm's attributes (see ClusterIDAttribute)
	// so callers can verify ownership before touching an existing realm.
	RealmExists(ctx context.Context, token, realm string) (found bool, attributes map[string]string, err error)
	// CreateRealm stamps ClusterIDAttribute=clusterID on the new realm.
	CreateRealm(ctx context.Context, token, realm, clusterID string) error
	DeleteRealm(ctx context.Context, token, realm string) error

	// FindClient also surfaces the client's attributes (see ClusterIDAttribute)
	// so callers can verify ownership before touching an existing client.
	FindClient(ctx context.Context, token, realm, clientName string) (id string, attributes map[string]string, found bool, err error)
	CreateClient(ctx context.Context, token, realm string, payload ClientPayload) (id string, err error)
	UpdateClient(ctx context.Context, token, realm, id string, payload ClientPayload) error
	DeleteClient(ctx context.Context, token, realm, id string) error
	ClientSecret(ctx context.Context, token, realm, id string) (secret string, ok bool, err error)
	GenerateClientSecret(ctx context.Context, token, realm, id string) (secret string, err error)

	FindClientScope(ctx context.Context, token, realm, scopeName string) (id string, found bool, err error)
	// CreateClientScopeWithAudienceMapper creates scopeName and attaches its
	// audience protocol mapper in one step — the only way scope.py's
	// ensure_access_scope ever creates a scope, so there's no case where a
	// scope needs to exist without its mapper.
	CreateClientScopeWithAudienceMapper(ctx context.Context, token, realm, scopeName, audience string) (id string, err error)
	// EnsureClientScopeAudience updates scopeID's existing audience mapper to
	// carry audience, if it doesn't already — needed because
	// CreateClientScopeWithAudienceMapper only ever sets this at creation, so
	// a scope created under an old audience convention would otherwise never
	// pick up a new one.
	EnsureClientScopeAudience(ctx context.Context, token, realm, scopeID, audience string) error
	DeleteClientScope(ctx context.Context, token, realm, scopeID string) error
	ClientOptionalScopeIDs(ctx context.Context, token, realm, clientID string) ([]string, error)
	AttachOptionalScope(ctx context.Context, token, realm, clientID, scopeID string) error
	// ClientDefaultScopeIDs/DetachDefaultScope let client.go's
	// demoteDefaultScopesToOptional move a freshly created client's
	// realm-inherited default scopes (profile/email/roles/web-origins/acr)
	// down to optional — left as default, the "roles" scope's
	// audience-resolve mapper silently injects Keycloak's own "account"
	// client into aud, turning a token's audience into a multi-valued array
	// instead of the single clean value most consumers (including AWS's OIDC
	// trust conditions) expect. myceliam's own per-profile scopes stay
	// optional too (see scope.go's ensureAccessScope) — a caller must
	// explicitly request them.
	ClientDefaultScopeIDs(ctx context.Context, token, realm, clientID string) ([]string, error)
	DetachDefaultScope(ctx context.Context, token, realm, clientID, scopeID string) error
}
