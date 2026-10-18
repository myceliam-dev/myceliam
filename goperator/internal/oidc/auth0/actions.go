// actions.go provisions the one tenant-wide Auth0 Action every myceliam
// Application relies on to get cloudmodels.Auth0ServiceAccountClaim (and its
// descriptive siblings) into issued tokens — see client.go's package doc
// comment for why this exists at all (Auth0 has no custom client_id, so
// myceliam self-issues its identity claim via client_metadata + this Action
// instead of relying on Auth0's own azp).
//
// Confirmed working end to end this session against a real tenant: a real
// issued token carried myceliam_service_account (and namespace/cluster_id/
// cloud) with the exact values this package writes into client_metadata, via
// an Action created and bound as described here. These claim names are
// plain, not URI-namespaced — see cloudmodels.Auth0ServiceAccountClaim's doc
// comment for why that's fine despite Auth0's own docs suggesting otherwise.
//
// The same four values are also projected into AWS's session-tags claim
// (https://aws.amazon.com/tags) so an account owner can write an AWS role
// trust policy that discriminates per-SA even though AWS can't reference the
// plain custom claims directly — see actionScript's own doc comment for the
// full mechanism, confirmed live end to end including the negative case.
//
// Provisioned lazily, idempotently, from EnsureTenant (called on every SA
// reconcile) — cached in-process after the first successful check so a
// steady-state operator doesn't re-verify this on every reconcile, only
// once per process lifetime (or after a restart).
package auth0

import (
	"context"
)

const (
	actionName                 = "myceliam-service-account-claims"
	credentialsExchangeTrigger = "credentials-exchange"
	triggerVersion             = "v2"
)

// actionScript is deployed verbatim — see §1 of the design: reads whichever
// of the four client_metadata keys this package sets and projects each into
// its own claim, a no-op for any client with none of them set. Claim names
// are plain ("myceliam_service_account", not a URI) — see
// cloudmodels.Auth0ServiceAccountClaim's doc comment.
//
// Also projects the same four values into "https://aws.amazon.com/tags"
// (AWS's documented session-tags-via-AssumeRoleWithWebIdentity claim — IAM
// User Guide, "Pass session tags in AWS STS"), each as a single-element
// array under principal_tags. Confirmed live end to end: with a role trust
// policy that additionally allows sts:TagSession, AWS applies these as real
// IAM principal tags, usable via aws:RequestTag/<key> directly in the trust
// policy's own Condition (gating AssumeRoleWithWebIdentity itself — verified
// both a matching value succeeding and a mismatched one failing outright
// with AccessDenied) or aws:PrincipalTag/<key> in downstream policies. This
// is what actually restores per-SA AWS discrimination despite one shared
// Auth0 Application per namespace, since a raw trust-policy condition on the
// bare claim name (e.g. "<provider>:myceliam_service_account") never
// matches — AWS only exposes claims declared in the provider's OIDC
// discovery document there, which never lists an Action-injected claim.
// Each principal_tags array MUST hold exactly one string — AWS rejects the
// entire token outright with InvalidIdentityToken (no index selection, no
// graceful degradation) if any array here ever has more than one entry;
// myceliam_cloud's comma-joined value ("gcp,aws") is fine, since it's still
// one string.
//
// Still registration-only on myceliam's side: this only emits the claim.
// Actually granting sts:TagSession and writing the aws:RequestTag/
// aws:PrincipalTag condition remains the account owner's job, the same as
// every other AWS role trust-policy edit myceliam has always left to them.
const actionScript = `exports.onExecuteCredentialsExchange = async (event, api) => {
  const md = event.client.metadata || {};
  const claims = {
    service_account: 'myceliam_service_account',
    namespace: 'myceliam_namespace',
    cluster_id: 'myceliam_cluster_id',
    cloud: 'myceliam_cloud',
  };
  const principalTags = {};
  for (const key of Object.keys(claims)) {
    if (md[key]) {
      api.accessToken.setCustomClaim(claims[key], md[key]);
      principalTags[claims[key]] = [md[key]];
    }
  }
  if (Object.keys(principalTags).length > 0) {
    api.accessToken.setCustomClaim('https://aws.amazon.com/tags', {
      principal_tags: principalTags,
    });
  }
};`

type auth0Action struct {
	ID                 string `json:"id,omitempty"`
	Name               string `json:"name,omitempty"`
	Code               string `json:"code,omitempty"`
	AllChangesDeployed bool   `json:"all_changes_deployed,omitempty"`
}

type actionBinding struct {
	Ref auth0ActionRef `json:"ref"`
}

type auth0ActionRef struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ensureAction is EnsureTenant's real work — see package doc comment for why
// it's cached rather than re-verified on every call.
func (p *Provider) ensureAction(ctx context.Context) error {
	action, found, err := p.findActionByName(ctx, actionName)
	if err != nil {
		return err
	}
	if !found {
		created := map[string]any{
			"name": actionName,
			"supported_triggers": []map[string]string{
				{"id": credentialsExchangeTrigger, "version": triggerVersion},
			},
			"code":    actionScript,
			"runtime": "node18",
		}
		var out auth0Action
		if err := p.doRequest(ctx, "POST", "/actions/actions", created, &out); err != nil {
			return err
		}
		action = &out
		if err := p.doRequest(ctx, "POST", "/actions/actions/"+action.ID+"/deploy", nil, nil); err != nil {
			return err
		}
	} else if err := p.ensureActionCodeCurrent(ctx, action.ID); err != nil {
		return err
	}
	return p.ensureActionBound(ctx, action.ID)
}

// ensureActionCodeCurrent keeps an already-provisioned Action's deployed
// code in sync with actionScript, AND makes sure it's actually deployed at
// all — not just that its code matches. Without the content check, a tenant
// provisioned by an older myceliam build (e.g. before claim names here were
// simplified from URI-namespaced to plain) would keep running stale code
// forever, since findActionByName only checks existence by name, never
// content. Without the all_changes_deployed check, an Action that exists
// with already-current code but was never deployed (e.g. created manually,
// or left mid-provisioning by an earlier failed run) would be silently
// skipped here and then rejected by ensureActionBound with "Trying to
// create a binding for an action that has not been deployed yet" — confirmed
// live against a real tenant in exactly this state. Fetches the individual
// Action (not the list endpoint findActionByName already used) since list
// responses aren't guaranteed to include the full code/all_changes_deployed
// fields.
func (p *Provider) ensureActionCodeCurrent(ctx context.Context, actionID string) error {
	var current auth0Action
	if err := p.doRequest(ctx, "GET", "/actions/actions/"+actionID, nil, &current); err != nil {
		return err
	}
	if current.Code == actionScript && current.AllChangesDeployed {
		return nil
	}
	if current.Code != actionScript {
		if err := p.doRequest(ctx, "PATCH", "/actions/actions/"+actionID, map[string]any{"code": actionScript}, nil); err != nil {
			return err
		}
	}
	return p.doRequest(ctx, "POST", "/actions/actions/"+actionID+"/deploy", nil, nil)
}

// findActionByName lists every Action and filters client-side by name — same
// reasoning as findAppByName/findResourceServerByAudience: don't trust a
// server-side name filter without checking it against a live tenant first.
func (p *Provider) findActionByName(ctx context.Context, name string) (*auth0Action, bool, error) {
	var resp struct {
		Actions []auth0Action `json:"actions"`
	}
	if err := p.doRequest(ctx, "GET", "/actions/actions?per_page=100", nil, &resp); err != nil {
		return nil, false, err
	}
	for _, a := range resp.Actions {
		if a.Name == name {
			return &a, true, nil
		}
	}
	return nil, false, nil
}

// ensureActionBound adds actionID to the credentials-exchange trigger's
// binding list if it isn't already there — reading the existing list first
// and appending, never replacing it wholesale, since other Actions an admin
// bound to this same trigger independently of myceliam must survive.
func (p *Provider) ensureActionBound(ctx context.Context, actionID string) error {
	var resp struct {
		Bindings []struct {
			Action auth0Action `json:"action"`
		} `json:"bindings"`
	}
	if err := p.doRequest(ctx, "GET", "/actions/triggers/"+credentialsExchangeTrigger+"/bindings", nil, &resp); err != nil {
		return err
	}
	for _, b := range resp.Bindings {
		if b.Action.ID == actionID {
			return nil
		}
	}

	bindings := make([]actionBinding, 0, len(resp.Bindings)+1)
	for _, b := range resp.Bindings {
		bindings = append(bindings, actionBinding{Ref: auth0ActionRef{Type: "action_id", Value: b.Action.ID}})
	}
	bindings = append(bindings, actionBinding{Ref: auth0ActionRef{Type: "action_id", Value: actionID}})

	return p.doRequest(ctx, "PATCH", "/actions/triggers/"+credentialsExchangeTrigger+"/bindings", map[string]any{"bindings": bindings}, nil)
}
