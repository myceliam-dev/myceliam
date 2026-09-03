package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Nerzal/gocloak/v13"
)

// gocloakAdmin is the real AdminAPI implementation, backed by
// github.com/Nerzal/gocloak/v13. All gocloak-specific concerns (pointer
// fields, *gocloak.APIError 404 detection) are encapsulated here so the rest
// of this package (client.go, scope.go) never imports gocloak directly.
type gocloakAdmin struct {
	gc        *gocloak.GoCloak
	serverURL string
}

func newGocloakAdmin(gc *gocloak.GoCloak, serverURL string) *gocloakAdmin {
	return &gocloakAdmin{gc: gc, serverURL: strings.TrimRight(serverURL, "/")}
}

func isNotFound(err error) bool {
	var apiErr *gocloak.APIError
	return errors.As(err, &apiErr) && apiErr.Code == 404
}

// safeStrMap dereferences gocloak's *map[string]string attribute fields,
// returning an empty (non-nil) map when absent so callers can index it
// without a nil check.
func safeStrMap(m *map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return *m
}

func (a *gocloakAdmin) RealmExists(ctx context.Context, token, realm string) (bool, map[string]string, error) {
	rep, err := a.gc.GetRealm(ctx, token, realm)
	if err == nil {
		return true, safeStrMap(rep.Attributes), nil
	}
	if isNotFound(err) {
		return false, nil, nil
	}
	return false, nil, err
}

func (a *gocloakAdmin) CreateRealm(ctx context.Context, token, realm, clusterID string) error {
	_, err := a.gc.CreateRealm(ctx, token, gocloak.RealmRepresentation{
		Realm:      gocloak.StringP(realm),
		Enabled:    gocloak.BoolP(true),
		Attributes: &map[string]string{ClusterIDAttribute: clusterID},
	})
	// A 409 here means another reconcile won the race to create this realm
	// first (see the equivalent race in ensure_tenant's docstring in
	// pythonoperator's client.py) — callers treat any CreateRealm error as
	// retryable, so surfacing it as-is is enough; the next attempt's
	// RealmExists will see the winner's realm and return early.
	return err
}

func (a *gocloakAdmin) DeleteRealm(ctx context.Context, token, realm string) error {
	return a.gc.DeleteRealm(ctx, token, realm)
}

func (a *gocloakAdmin) FindClient(ctx context.Context, token, realm, clientName string) (string, map[string]string, bool, error) {
	clients, err := a.gc.GetClients(ctx, token, realm, gocloak.GetClientsParams{ClientID: gocloak.StringP(clientName)})
	if err != nil {
		return "", nil, false, err
	}
	for _, c := range clients {
		if c.ClientID != nil && *c.ClientID == clientName {
			return safeStr(c.ID), safeStrMap(c.Attributes), true, nil
		}
	}
	return "", nil, false, nil
}

func toGocloakClient(payload ClientPayload) gocloak.Client {
	attrs := make(map[string]string, len(payload.Attributes))
	for k, v := range payload.Attributes {
		attrs[k] = v
	}
	return gocloak.Client{
		ClientID:                  gocloak.StringP(payload.ClientID),
		Enabled:                   gocloak.BoolP(payload.Enabled),
		Protocol:                  gocloak.StringP(payload.Protocol),
		PublicClient:              gocloak.BoolP(payload.PublicClient),
		ServiceAccountsEnabled:    gocloak.BoolP(payload.ServiceAccountsEnabled),
		StandardFlowEnabled:       gocloak.BoolP(payload.StandardFlowEnabled),
		DirectAccessGrantsEnabled: gocloak.BoolP(payload.DirectAccessGrantsEnabled),
		ClientAuthenticatorType:   gocloak.StringP(payload.ClientAuthenticatorType),
		Attributes:                &attrs,
	}
}

func (a *gocloakAdmin) CreateClient(ctx context.Context, token, realm string, payload ClientPayload) (string, error) {
	return a.gc.CreateClient(ctx, token, realm, toGocloakClient(payload))
}

func (a *gocloakAdmin) UpdateClient(ctx context.Context, token, realm, id string, payload ClientPayload) error {
	client := toGocloakClient(payload)
	client.ID = gocloak.StringP(id)
	return a.gc.UpdateClient(ctx, token, realm, client)
}

func (a *gocloakAdmin) DeleteClient(ctx context.Context, token, realm, id string) error {
	return a.gc.DeleteClient(ctx, token, realm, id)
}

func (a *gocloakAdmin) ClientSecret(ctx context.Context, token, realm, id string) (string, bool, error) {
	cred, err := a.gc.GetClientSecret(ctx, token, realm, id)
	if err != nil {
		if isNotFound(err) {
			return "", false, nil
		}
		return "", false, err
	}
	secret := safeStr(cred.Value)
	return secret, secret != "", nil
}

func (a *gocloakAdmin) GenerateClientSecret(ctx context.Context, token, realm, id string) (string, error) {
	cred, err := a.gc.RegenerateClientSecret(ctx, token, realm, id)
	if err != nil {
		return "", err
	}
	return safeStr(cred.Value), nil
}

func (a *gocloakAdmin) FindClientScope(ctx context.Context, token, realm, scopeName string) (string, bool, error) {
	scopes, err := a.gc.GetClientScopes(ctx, token, realm)
	if err != nil {
		return "", false, err
	}
	for _, s := range scopes {
		if s.Name != nil && *s.Name == scopeName {
			return safeStr(s.ID), true, nil
		}
	}
	return "", false, nil
}

// audienceMapperPayload is the oidc-audience-mapper body shared by mapper
// creation (fresh scope, or an existing one somehow missing its mapper) and
// audienceMapperConfig's own update-in-place path below. Its "included.custom.
// audience" config key has no field on gocloak's typed ProtocolMappersConfig
// (it only exposes "included.client.audience", for targeting another
// registered client rather than an arbitrary string) — so every call here
// goes straight to the Admin REST API instead of through gocloak's typed
// helper, the same "raw REST where the typed client doesn't cover it" pattern
// pythonoperator's cloud_providers/gcp.py already uses for GCP.
func audienceMapperPayload(audience string) map[string]any {
	return map[string]any{
		"name":           "audience",
		"protocol":       "openid-connect",
		"protocolMapper": "oidc-audience-mapper",
		"config": map[string]string{
			"included.custom.audience": audience,
			"id.token.claim":           "false",
			"access.token.claim":       "true",
		},
	}
}

// CreateClientScopeWithAudienceMapper creates scopeName and attaches an
// oidc-audience-mapper carrying `audience`.
func (a *gocloakAdmin) CreateClientScopeWithAudienceMapper(ctx context.Context, token, realm, scopeName, audience string) (string, error) {
	scopeID, err := a.gc.CreateClientScope(ctx, token, realm, gocloak.ClientScope{
		Name:     gocloak.StringP(scopeName),
		Protocol: gocloak.StringP("openid-connect"),
	})
	if err != nil {
		// A 409 here means another reconcile won the race to create this
		// scope first — treated as retryable, same as CreateRealm above.
		return "", err
	}

	resp, err := a.gc.RestyClient().R().
		SetContext(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json").
		SetBody(audienceMapperPayload(audience)).
		Post(fmt.Sprintf("%s/admin/realms/%s/client-scopes/%s/protocol-mappers/models", a.serverURL, realm, scopeID))
	if err != nil {
		return "", fmt.Errorf("creating audience mapper for client scope %q: %w", scopeName, err)
	}
	if resp.IsError() {
		return "", fmt.Errorf("creating audience mapper for client scope %q: %s: %s", scopeName, resp.Status(), resp.String())
	}
	return scopeID, nil
}

type genericProtocolMapper struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Protocol       string            `json:"protocol"`
	ProtocolMapper string            `json:"protocolMapper"`
	Config         map[string]string `json:"config"`
}

// EnsureClientScopeAudience makes sure scopeID's "audience" oidc-audience-mapper
// carries the given value, updating it in place if it already exists with a
// different one. Needed because CreateClientScopeWithAudienceMapper only ever
// sets this at creation — without this, changing what audience a scope should
// carry (e.g. adopting a new naming convention) would silently never take
// effect for any scope that already existed.
func (a *gocloakAdmin) EnsureClientScopeAudience(ctx context.Context, token, realm, scopeID, audience string) error {
	resp, err := a.gc.RestyClient().R().
		SetContext(ctx).
		SetAuthToken(token).
		Get(fmt.Sprintf("%s/admin/realms/%s/client-scopes/%s/protocol-mappers/models", a.serverURL, realm, scopeID))
	if err != nil {
		return fmt.Errorf("listing protocol mappers for client scope %q: %w", scopeID, err)
	}
	if resp.IsError() {
		return fmt.Errorf("listing protocol mappers for client scope %q: %s: %s", scopeID, resp.Status(), resp.String())
	}
	var mappers []genericProtocolMapper
	if err := json.Unmarshal(resp.Body(), &mappers); err != nil {
		return fmt.Errorf("decoding protocol mappers for client scope %q: %w", scopeID, err)
	}

	for _, m := range mappers {
		if m.Name != "audience" {
			continue
		}
		if m.Config["included.custom.audience"] == audience {
			return nil
		}
		m.Config["included.custom.audience"] = audience
		updateResp, err := a.gc.RestyClient().R().
			SetContext(ctx).
			SetAuthToken(token).
			SetHeader("Content-Type", "application/json").
			SetBody(map[string]any{
				"id":             m.ID,
				"name":           m.Name,
				"protocol":       m.Protocol,
				"protocolMapper": m.ProtocolMapper,
				"config":         m.Config,
			}).
			Put(fmt.Sprintf("%s/admin/realms/%s/client-scopes/%s/protocol-mappers/models/%s", a.serverURL, realm, scopeID, m.ID))
		if err != nil {
			return fmt.Errorf("updating audience mapper for client scope %q: %w", scopeID, err)
		}
		if updateResp.IsError() {
			return fmt.Errorf("updating audience mapper for client scope %q: %s: %s", scopeID, updateResp.Status(), updateResp.String())
		}
		return nil
	}

	// No "audience" mapper at all — shouldn't normally happen (creation
	// always adds one), but create it now rather than leaving the scope
	// carrying no audience.
	createResp, err := a.gc.RestyClient().R().
		SetContext(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json").
		SetBody(audienceMapperPayload(audience)).
		Post(fmt.Sprintf("%s/admin/realms/%s/client-scopes/%s/protocol-mappers/models", a.serverURL, realm, scopeID))
	if err != nil {
		return fmt.Errorf("creating audience mapper for client scope %q: %w", scopeID, err)
	}
	if createResp.IsError() {
		return fmt.Errorf("creating audience mapper for client scope %q: %s: %s", scopeID, createResp.Status(), createResp.String())
	}
	return nil
}

func (a *gocloakAdmin) DeleteClientScope(ctx context.Context, token, realm, scopeID string) error {
	return a.gc.DeleteClientScope(ctx, token, realm, scopeID)
}

func (a *gocloakAdmin) ClientOptionalScopeIDs(ctx context.Context, token, realm, clientID string) ([]string, error) {
	scopes, err := a.gc.GetClientsOptionalScopes(ctx, token, realm, clientID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(scopes))
	for _, s := range scopes {
		ids = append(ids, safeStr(s.ID))
	}
	return ids, nil
}

func (a *gocloakAdmin) AttachOptionalScope(ctx context.Context, token, realm, clientID, scopeID string) error {
	return a.gc.AddOptionalScopeToClient(ctx, token, realm, clientID, scopeID)
}

func (a *gocloakAdmin) ClientDefaultScopeIDs(ctx context.Context, token, realm, clientID string) ([]string, error) {
	scopes, err := a.gc.GetClientsDefaultScopes(ctx, token, realm, clientID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(scopes))
	for _, s := range scopes {
		ids = append(ids, safeStr(s.ID))
	}
	return ids, nil
}

func (a *gocloakAdmin) DetachDefaultScope(ctx context.Context, token, realm, clientID, scopeID string) error {
	return a.gc.RemoveDefaultScopeFromClient(ctx, token, realm, clientID, scopeID)
}

func safeStr(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
