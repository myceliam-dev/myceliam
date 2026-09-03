package keycloak

import (
	"context"

	"myceliam/internal/operr"
)

// ensureAccessScope ensures a client scope named scopeName exists in realm,
// carries an Audience protocol mapper injecting the fixed audience value into
// the token, and is attached to clientName as an optional client scope — a
// caller must explicitly request scope=scopeName to get it in a token, kept
// deliberately opt-in rather than default so a client's token stays minimal
// unless something actually asks for this specific federation audience.
//
// Unlike scope.py's ensure_access_scope, this takes no "manager" back-reference
// for realm-switching (see adminapi.go's AdminAPI doc comment on why no
// equivalent of _for_realm's lock exists here) — just the admin API, an
// already-fetched token, and realm as a plain parameter.
func ensureAccessScope(ctx context.Context, admin AdminAPI, token, realm, clientName, scopeName, audience string) error {
	scopeID, found, err := admin.FindClientScope(ctx, token, realm, scopeName)
	if err != nil {
		return operr.Temporaryf(adminCallDelay, "Error ensuring access scope '%s' for client '%s' in realm '%s': %v", scopeName, clientName, realm, err)
	}
	if !found {
		scopeID, err = admin.CreateClientScopeWithAudienceMapper(ctx, token, realm, scopeName, audience)
		if err != nil {
			return operr.Temporaryf(adminCallDelay, "Error ensuring access scope '%s' for client '%s' in realm '%s': %v", scopeName, clientName, realm, err)
		}
	} else if err := admin.EnsureClientScopeAudience(ctx, token, realm, scopeID, audience); err != nil {
		// A scope created under a since-changed audience convention
		// otherwise keeps whatever value it was originally given forever —
		// CreateClientScopeWithAudienceMapper above only sets this once, at
		// creation.
		return operr.Temporaryf(adminCallDelay, "Error ensuring access scope '%s' for client '%s' in realm '%s': %v", scopeName, clientName, realm, err)
	}

	clientID, _, found, err := admin.FindClient(ctx, token, realm, clientName)
	if err != nil {
		return operr.Temporaryf(adminCallDelay, "Error ensuring access scope '%s' for client '%s' in realm '%s': %v", scopeName, clientName, realm, err)
	}
	if !found {
		return operr.Temporaryf(adminCallDelay, "Client '%s' not found in realm '%s' yet; will retry", clientName, realm)
	}

	optionalScopeIDs, err := admin.ClientOptionalScopeIDs(ctx, token, realm, clientID)
	if err != nil {
		return operr.Temporaryf(adminCallDelay, "Error ensuring access scope '%s' for client '%s' in realm '%s': %v", scopeName, clientName, realm, err)
	}
	for _, id := range optionalScopeIDs {
		if id == scopeID {
			return nil
		}
	}

	if err := admin.AttachOptionalScope(ctx, token, realm, clientID, scopeID); err != nil {
		return operr.Temporaryf(adminCallDelay, "Error ensuring access scope '%s' for client '%s' in realm '%s': %v", scopeName, clientName, realm, err)
	}
	return nil
}

func deleteAccessScope(ctx context.Context, admin AdminAPI, token, realm, scopeName string) error {
	scopeID, found, err := admin.FindClientScope(ctx, token, realm, scopeName)
	if err != nil {
		return operr.Temporaryf(adminCallDelay, "Error deleting access scope '%s' in realm '%s': %v", scopeName, realm, err)
	}
	if !found {
		return nil
	}
	if err := admin.DeleteClientScope(ctx, token, realm, scopeID); err != nil {
		return operr.Temporaryf(adminCallDelay, "Error deleting access scope '%s' in realm '%s': %v", scopeName, realm, err)
	}
	return nil
}
