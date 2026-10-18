// clients.go manages Auth0 Applications — oidc.Provider's "client", one per
// ServiceAccount. Auth0 has no custom client_id (confirmed empirically), so
// Applications are looked up by their name field (set to the SA name)
// instead — see client.go's package doc comment for why the actual identity
// claim is self-issued via client_metadata + a tenant-wide Action instead of
// relying on Auth0's own azp.
package auth0

import (
	"context"
	"strings"

	"myceliam/internal/models"
	"myceliam/internal/operr"
)

type auth0App struct {
	ClientID       string            `json:"client_id,omitempty"`
	Name           string            `json:"name"`
	AppType        string            `json:"app_type"`
	ClientSecret   string            `json:"client_secret,omitempty"`
	ClientMetadata map[string]string `json:"client_metadata,omitempty"`
}

// namespaceFor recovers the plain namespace from spec.Realm
// (models.RealmForNamespace's "<cluster-id>-<namespace>" convention) —
// exact and unambiguous since p.settings.ClusterID is already a known,
// fixed string, regardless of hyphens in either part.
func (p *Provider) namespaceFor(spec *models.ClientSpec) string {
	return strings.TrimPrefix(spec.Realm, p.settings.ClusterID+"-")
}

func baseMetadata(p *Provider, spec *models.ClientSpec) map[string]string {
	return map[string]string{
		"cluster_id":      p.settings.ClusterID,
		"namespace":       p.namespaceFor(spec),
		"service_account": spec.ClientName,
	}
}

// findAppByName lists every Application and filters client-side by name —
// deliberately not a server-side filter: Management API list filters on
// platforms like this can silently reject or ignore fields you'd expect to
// be filterable, so default to the safe approach until this one is checked
// against a live tenant. Fine at the scale this package expects (a handful
// of myceliam-managed Applications per cluster).
//
// TODO: verify against a live tenant — confirm GET /api/v2/clients doesn't
// support (or does support) a reliable server-side name filter, and confirm
// pagination isn't silently truncating this list once there are many apps.
func (p *Provider) findAppByName(ctx context.Context, name string) (*auth0App, bool, error) {
	var apps []auth0App
	if err := p.doRequest(ctx, "GET", "/clients?fields=client_id,name,client_metadata&per_page=100", nil, &apps); err != nil {
		return nil, false, err
	}
	for _, a := range apps {
		if a.Name == name {
			return &a, true, nil
		}
	}
	return nil, false, nil
}

// ensureApp creates the Application with no token_endpoint_auth_method set
// at all — Auth0's POST /clients only accepts "none"/"client_secret_post"/
// "client_secret_basic" there (confirmed live: it rejects "private_key_jwt"
// outright with a 400 Payload validation error), and token_endpoint_auth_method/
// client_authentication_methods are mutually exclusive on this API anyway.
// A secret client just gets Auth0's default (client_secret_post); a
// signedjwt client's private_key_jwt auth is activated separately, after
// its credential exists, via EnsureSignedjwtClient's own PATCH — see its
// doc comment.
func (p *Provider) ensureApp(ctx context.Context, spec *models.ClientSpec) (*auth0App, error) {
	existing, found, err := p.findAppByName(ctx, spec.ClientName)
	if found {
		return existing, nil
	}
	if err != nil {
		return nil, err
	}

	app := auth0App{
		Name:           spec.ClientName,
		AppType:        "non_interactive",
		ClientMetadata: baseMetadata(p, spec),
	}
	var created auth0App
	if err := p.doRequest(ctx, "POST", "/clients", app, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// EnsureSecretClient returns (clientID, clientSecret) — clientID is
// Auth0-assigned (unlike Keycloak, it can't be set to the SA name; see
// client.go's package doc comment for why the trust condition doesn't rely
// on it). clientSecret is only returned by Auth0 on creation — re-ensuring
// an already-created app cannot recover it.
func (p *Provider) EnsureSecretClient(ctx context.Context, spec *models.ClientSpec) (clientID, clientSecret string, err error) {
	app, err := p.ensureApp(ctx, spec)
	if err != nil {
		return "", "", err
	}
	if app.ClientSecret == "" {
		return "", "", operr.Permanentf(
			"Auth0 Application for '%s' exists but has no client_secret available "+
				"(already created previously, and Auth0 only returns a secret once) — "+
				"delete the Application in Auth0 and let this reconcile again to mint a fresh one.",
			spec.ClientName,
		)
	}
	return app.ClientID, app.ClientSecret, nil
}

// credentialResponse is POST (and GET-list) /clients/{client_id}/credentials's
// item shape — only the fields this package needs. ID is the credential's
// own identifier (e.g. "cred_..."), distinct from Kid (the JWK thumbprint) —
// required to reference this exact credential in the
// client_authentication_methods PATCH below. Name round-trips whatever was
// sent at creation (see EnsureSignedjwtClient, which sets it to
// spec.ClientName), used to find this SA's own credential among any others
// on the same client without touching them.
type credentialResponse struct {
	ID   string `json:"id"`
	Kid  string `json:"kid"`
	Name string `json:"name"`
}

// findCredentialByName lists an Application's registered credentials and
// filters client-side by name — same reasoning as findAppByName/
// findResourceServerByAudience. Needed because Auth0's Client Credentials
// (public_key/private_key_jwt) entity has a documented HARD CAP that's
// tenant-wide, not per-client — confirmed live against a free/dev tenant
// (2 total across every Application combined) — so re-POSTing a credential
// on every reconcile retry isn't just wasteful, it permanently fails with
// "too_many_entities" the moment the tenant is at its cap, even though the
// credential from an earlier successful attempt is already sitting there
// unused because a prior run failed before reaching the activation PATCH
// below. Skipping straight to activation when one already exists is what
// actually recovers from that half-finished state.
func (p *Provider) findCredentialByName(ctx context.Context, appClientID, name string) (*credentialResponse, bool, error) {
	var creds []credentialResponse
	if err := p.doRequest(ctx, "GET", "/clients/"+appClientID+"/credentials", nil, &creds); err != nil {
		return nil, false, err
	}
	for _, c := range creds {
		if c.Name == name {
			return &c, true, nil
		}
	}
	return nil, false, nil
}

// EnsureSignedjwtClient registers certPEM's public key as the Application's
// private_key_jwt credential via the separate client-credentials endpoint,
// then activates it for token-endpoint authentication via a second PATCH —
// a genuine three-call sequence (create app, register credential, activate
// it). Confirmed live against a real tenant:
//   - POST /clients/{id}/credentials for credential_type "public_key" takes
//     a raw PEM certificate under "pem" — NOT a JWKS document ("jwks" is
//     silently ignored/rejected depending on shape; this package's own
//     jwksString is for Keycloak only, see oidc.Provider's doc comment).
//   - Registering the credential alone does not activate it. token_endpoint_
//     auth_method and client_authentication_methods are mutually exclusive
//     properties on a Client — the former only accepts "none"/
//     "client_secret_post"/"client_secret_basic" (confirmed live: it
//     rejects "private_key_jwt" outright with a 400), so private_key_jwt
//     must be turned on via a PATCH setting client_authentication_methods.
//     private_key_jwt.credentials to reference this credential's own id.
//   - That PATCH requires the operator's Auth0 Application to have the
//     update:client_credentials Management API scope — a prerequisite
//     alongside the scopes already listed in
//     deploy-operator/auth0/auth0-operator.yaml's header comment.
//
// findCredentialByName is checked first — see its own doc comment for why
// re-creating on every call is actively harmful here, not just redundant.
// NOTE: this does not detect cert rotation (a changed certPEM for an SA
// whose credential already exists here is not re-registered) — Auth0's
// tenant-wide credential cap makes "always keep the latest cert" and "never
// exceed the cap" hard to satisfy simultaneously without a delete-old-then-
// create-new sequence this package doesn't attempt yet. Revisit if signedjwt
// cert rotation on Auth0 is actually needed.
//
// The kid hint is ignored for the actual credential: Auth0 computes its own,
// independent of what's requested, per the JWK Thumbprint standard (RFC
// 7638) — same as the admin saw when registering the operator's own
// bootstrap credential (adminauth.go's Auth0OperatorKeypairKid doc comment).
// actualKid is read back from this call's own response rather than assumed,
// since that's the only value guaranteed to match what Auth0 will actually
// expect in a client assertion's header later.
func (p *Provider) EnsureSignedjwtClient(ctx context.Context, spec *models.ClientSpec, certPEM []byte, jwksString, kid string) (clientID, actualKid string, err error) {
	app, err := p.ensureApp(ctx, spec)
	if err != nil {
		return "", "", err
	}

	resp, found, err := p.findCredentialByName(ctx, app.ClientID, spec.ClientName)
	if err != nil {
		return "", "", err
	}
	if !found {
		created := map[string]any{
			"credential_type": "public_key",
			"name":            spec.ClientName,
			"pem":             string(certPEM),
		}
		var out credentialResponse
		if err := p.doRequest(ctx, "POST", "/clients/"+app.ClientID+"/credentials", created, &out); err != nil {
			return "", "", err
		}
		resp = &out
	}
	if resp.ID == "" || resp.Kid == "" {
		return "", "", operr.Permanentf(
			"Auth0 credential registration for '%s' returned no id/kid — cannot activate "+
				"private_key_jwt auth or tell the workload which key identifier to sign its "+
				"own client assertions with.",
			spec.ClientName,
		)
	}

	activation := map[string]any{
		// Required alongside client_authentication_methods — confirmed live:
		// Auth0 rejects the PATCH otherwise with "A JWT signing algorithm is
		// required to create a non `client_secret` based client, please
		// specify `jwt_configuration.alg`." RS256 matches both certgen's own
		// RSA keys (internal/certgen) and what the /credentials endpoint
		// itself defaults new public_key credentials to.
		"jwt_configuration": map[string]any{"alg": "RS256"},
		"client_authentication_methods": map[string]any{
			"private_key_jwt": map[string]any{
				"credentials": []map[string]string{{"id": resp.ID}},
			},
		},
	}
	if err := p.doRequest(ctx, "PATCH", "/clients/"+app.ClientID, activation, nil); err != nil {
		return "", "", err
	}
	return app.ClientID, resp.Kid, nil
}

// DeleteClient deletes the Application for clientName. No-op if it doesn't
// exist. Auth0's Applications API doesn't require a separate deactivate
// step before deletion (TODO: verify against a live tenant).
func (p *Provider) DeleteClient(ctx context.Context, tenantID, clientName string) error {
	app, found, err := p.findAppByName(ctx, clientName)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	return p.doRequest(ctx, "DELETE", "/clients/"+app.ClientID, nil, nil)
}
