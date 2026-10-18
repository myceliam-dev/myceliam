// resourceservers.go manages Auth0 "APIs" (Resource Servers) and Client
// Grants: a Client Grant directly links one client_id to one audience with
// a scope list, no intermediate policy/rule object required. One Resource
// Server exists per (cloud, cluster ID, namespace), named/keyed by its
// audience string — see cloudmodels.ParseCloudFederationSpecs's doc comment.
package auth0

import (
	"context"
	"strings"

	"myceliam/internal/operr"
)

type resourceServer struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name"`
	Identifier string `json:"identifier"`
}

type clientGrant struct {
	ID       string   `json:"id,omitempty"`
	ClientID string   `json:"client_id"`
	Audience string   `json:"audience"`
	Scope    []string `json:"scope"`
}

// findResourceServerByAudience lists every Resource Server and returns the
// one whose Identifier matches audience — client-side filtering, same
// reasoning as findAppByName (verify a server-side identifier filter isn't
// available/reliable before trusting one).
func (p *Provider) findResourceServerByAudience(ctx context.Context, audience string) (*resourceServer, bool, error) {
	var servers []resourceServer
	if err := p.doRequest(ctx, "GET", "/resource-servers?per_page=100", nil, &servers); err != nil {
		return nil, false, err
	}
	for _, s := range servers {
		if s.Identifier == audience {
			return &s, true, nil
		}
	}
	return nil, false, nil
}

func (p *Provider) ensureResourceServer(ctx context.Context, audience string) (*resourceServer, error) {
	rs, found, err := p.findResourceServerByAudience(ctx, audience)
	if err != nil {
		return nil, err
	}
	if found {
		return rs, nil
	}
	created := resourceServer{Name: audience, Identifier: audience}
	if err := p.doRequest(ctx, "POST", "/resource-servers", created, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// resolveClientID translates clientName (a ServiceAccount's own name, what
// oidc.Provider.EnsureAccessScope/DeleteAccessScope's clientName parameter
// actually carries — see their own doc comments) into Auth0's real,
// opaque client_id. Required here specifically: unlike Keycloak, where
// a client's client_id IS the ServiceAccount name by construction, Auth0
// assigns its own random client_id (see client.go's package doc comment) —
// passing clientName directly to a client-grants/client_metadata call
// against Auth0's API 404s with "Client not found", confirmed live. Returns
// an *operr.Temporary (not Permanent) when the Application doesn't exist
// yet: EnsureAccessScope can legitimately run before reconcileClient has
// created it, depending on reconcile ordering.
func (p *Provider) resolveClientID(ctx context.Context, clientName string) (string, error) {
	app, found, err := p.findAppByName(ctx, clientName)
	if err != nil {
		return "", err
	}
	if !found {
		return "", operr.Temporaryf(adminCallDelay, "Auth0 Application for '%s' not found yet; will retry", clientName)
	}
	return app.ClientID, nil
}

func (p *Provider) findClientGrant(ctx context.Context, clientID, audience string) (*clientGrant, bool, error) {
	var grants []clientGrant
	if err := p.doRequest(ctx, "GET", "/client-grants?audience="+audience+"&per_page=100", nil, &grants); err != nil {
		return nil, false, err
	}
	for _, g := range grants {
		if g.ClientID == clientID {
			return &g, true, nil
		}
	}
	return nil, false, nil
}

// EnsureAccessScope grants clientID a Client Grant against the Resource
// Server for audience (creating the Resource Server first if absent), and
// accumulates cloud into the Application's comma-separated client_metadata
// "cloud" list — descriptive/audit only, not what the trust condition
// matches on (that's cloudmodels.Auth0ServiceAccountClaim, projected from
// "service_account" by the tenant-wide Action — see client.go's package doc
// comment). scopeName carries no separate meaning here — audience alone
// identifies everything needed.
//
// TODO: verify against a live tenant — whether PATCH /clients/{id} with a
// partial client_metadata object merges with existing keys or replaces the
// whole object; this implementation assumes merge (reading the full
// existing metadata first and writing it back with "cloud" changed) to be
// safe either way, but hasn't been confirmed against a real tenant.
//
// Its azpValue return is clientID itself — Auth0's own dynamically-assigned
// client_id, which is what its issued tokens actually carry as azp (Auth0
// has no custom-client_id support, unlike Keycloak — see
// oidc.Provider.EnsureAccessScope's doc comment for why callers need this).
// Returning the value resolveClientID already looked up here spares the
// caller a second live Management API call just to learn it.
func (p *Provider) EnsureAccessScope(ctx context.Context, tenantID, clientName, scopeName, audience string) (string, error) {
	clientID, err := p.resolveClientID(ctx, clientName)
	if err != nil {
		return "", err
	}
	if _, err := p.ensureResourceServer(ctx, audience); err != nil {
		return "", err
	}

	if _, found, err := p.findClientGrant(ctx, clientID, audience); err != nil {
		return "", err
	} else if !found {
		grant := clientGrant{ClientID: clientID, Audience: audience, Scope: []string{}}
		if err := p.doRequest(ctx, "POST", "/client-grants", grant, nil); err != nil {
			return "", err
		}
	}

	cloud := audience[:strings.IndexByte(audience, '-')]
	if err := p.addCloudToMetadata(ctx, clientID, cloud); err != nil {
		return "", err
	}
	return clientID, nil
}

// ensureOperatorAccessScope is GetOperatorToken's one-time setup: it
// provisions a Resource Server for Settings.Auth0OperatorAudience and a
// Client Grant letting Settings.Auth0OperatorClientID request tokens against
// it — the operator-identity analogue of EnsureAccessScope, minus the
// client_metadata bookkeeping (the operator's own Application has no
// namespace/service_account/cloud identity to project; AWS/GCP trust
// conditions for the operator's own bootstrap role are matched on whatever
// the admin configured out of band, same as OperatorSpiffeAudience's own
// doc comment already describes for the spiffe path). Uses p.auth (the
// Management API credential) to provision, then p.operatorAuth (a different
// audience) to actually mint the token — see GetOperatorToken. Cached via
// Provider.operatorScopeEnsured, same not-sync.Once reasoning as
// actionEnsured: a transient failure must retry on the next call, not be
// permanently cached as success.
func (p *Provider) ensureOperatorAccessScope(ctx context.Context) error {
	p.operatorScopeMu.Lock()
	defer p.operatorScopeMu.Unlock()
	if p.operatorScopeEnsured {
		return nil
	}

	audience := p.settings.Auth0OperatorAudience
	clientID := p.settings.Auth0OperatorClientID
	if _, err := p.ensureResourceServer(ctx, audience); err != nil {
		return err
	}
	if _, found, err := p.findClientGrant(ctx, clientID, audience); err != nil {
		return err
	} else if !found {
		grant := clientGrant{ClientID: clientID, Audience: audience, Scope: []string{}}
		if err := p.doRequest(ctx, "POST", "/client-grants", grant, nil); err != nil {
			return err
		}
	}

	p.operatorScopeEnsured = true
	return nil
}

// addCloudToMetadata reads the Application's current client_metadata,
// appends cloud to its comma-separated "cloud" value if not already present,
// and writes the full metadata object back (see EnsureAccessScope's TODO on
// merge-vs-replace semantics).
func (p *Provider) addCloudToMetadata(ctx context.Context, clientID, cloud string) error {
	var app auth0App
	if err := p.doRequest(ctx, "GET", "/clients/"+clientID+"?fields=client_id,client_metadata", nil, &app); err != nil {
		return err
	}
	md := app.ClientMetadata
	if md == nil {
		md = map[string]string{}
	}
	clouds := splitNonEmpty(md["cloud"], ",")
	for _, c := range clouds {
		if c == cloud {
			return nil // already present, nothing to do
		}
	}
	clouds = append(clouds, cloud)
	md["cloud"] = strings.Join(clouds, ",")
	return p.doRequest(ctx, "PATCH", "/clients/"+clientID, map[string]any{"client_metadata": md}, nil)
}

// removeCloudFromMetadata is addCloudToMetadata's inverse, used by
// DeleteAccessScope.
func (p *Provider) removeCloudFromMetadata(ctx context.Context, clientID, cloud string) error {
	var app auth0App
	if err := p.doRequest(ctx, "GET", "/clients/"+clientID+"?fields=client_id,client_metadata", nil, &app); err != nil {
		return err
	}
	md := app.ClientMetadata
	if md == nil {
		return nil
	}
	clouds := splitNonEmpty(md["cloud"], ",")
	remaining := clouds[:0]
	for _, c := range clouds {
		if c != cloud {
			remaining = append(remaining, c)
		}
	}
	md["cloud"] = strings.Join(remaining, ",")
	return p.doRequest(ctx, "PATCH", "/clients/"+clientID, map[string]any{"client_metadata": md}, nil)
}

func splitNonEmpty(s, sep string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, sep)
}

// DeleteAccessScope deletes the Client Grant for (clientID, scopeName/audience
// — Auth0 ignores scopeName, using audience directly) and symmetrically
// removes it from the Application's "cloud" metadata. Once no Client Grant
// references the Resource Server, it's deleted too — unconfirmed whether
// Auth0 Resource Servers are scarce enough for this to matter in practice.
func (p *Provider) DeleteAccessScope(ctx context.Context, tenantID, clientName, scopeName string) error {
	rs, found, err := p.findResourceServerByAudience(ctx, scopeName)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}

	app, found, err := p.findAppByName(ctx, clientName)
	if err != nil {
		return err
	}
	if !found {
		// Nothing to revoke for a client that no longer exists — cleanup is
		// idempotent/no-op here, matching DeleteClient's own semantics for a
		// missing Application, unlike EnsureAccessScope's resolveClientID
		// (which retries instead, since ensuring access legitimately needs
		// the Application to exist first).
		return nil
	}
	clientID := app.ClientID

	grant, found, err := p.findClientGrant(ctx, clientID, scopeName)
	if err != nil {
		return err
	}
	if found {
		if err := p.doRequest(ctx, "DELETE", "/client-grants/"+grant.ID, nil, nil); err != nil {
			return err
		}
	}

	cloud := scopeName[:strings.IndexByte(scopeName, '-')]
	if err := p.removeCloudFromMetadata(ctx, clientID, cloud); err != nil {
		return err
	}

	var remaining []clientGrant
	if err := p.doRequest(ctx, "GET", "/client-grants?audience="+scopeName+"&per_page=1", nil, &remaining); err != nil {
		return err
	}
	if len(remaining) == 0 {
		return p.doRequest(ctx, "DELETE", "/resource-servers/"+rs.ID, nil, nil)
	}
	return nil
}

// deleteResourceServerAndGrants force-deletes the Resource Server for
// audience along with every Client Grant against it, regardless of whether
// any still exist — the namespace-teardown-time counterpart to
// DeleteAccessScope's own last-one-out cleanup (which only fires once a
// specific client's own grant removal happens to leave zero remaining). No-op
// if the Resource Server doesn't exist. See DeleteTenant's own doc comment
// for why this sweep exists at all: unlike Keycloak's realm, there's no
// single container whose deletion would cascade this away, so a leftover
// grant (e.g. from an SA whose own finalizer-triggered cleanup never ran —
// force-deleted, or failed and got stuck) would otherwise block
// EnsureAccessScope's own resource-server reuse forever, and the Resource
// Server itself would never be reclaimed.
func (p *Provider) deleteResourceServerAndGrants(ctx context.Context, audience string) error {
	rs, found, err := p.findResourceServerByAudience(ctx, audience)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	var grants []clientGrant
	if err := p.doRequest(ctx, "GET", "/client-grants?audience="+audience+"&per_page=100", nil, &grants); err != nil {
		return err
	}
	for _, g := range grants {
		if err := p.doRequest(ctx, "DELETE", "/client-grants/"+g.ID, nil, nil); err != nil {
			return err
		}
	}
	return p.doRequest(ctx, "DELETE", "/resource-servers/"+rs.ID, nil, nil)
}
