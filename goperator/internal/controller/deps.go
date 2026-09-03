// Package controller ports pythonoperator/src/myceliam/handlers.py: the kopf
// handler set, as controller-runtime reconcilers over the same watched
// resources (core ServiceAccount/Namespace/Secret, and the two
// myceliam.io/v1 CRDs).
package controller

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	"myceliam/internal/config"
	"myceliam/internal/oidc"
)

// finalizerName is the Go equivalent of the finalizer kopf transparently
// manages around every @kopf.on.delete handler — here made explicit (one
// shared name across every reconciler that needs it), since controller-runtime
// has no equivalent auto-finalizer.
const finalizerName = "myceliam.io/finalizer"

// Deps is the shared state every reconciler needs — the Go equivalent of
// kopf's memo (memo.settings / memo.oidc), built once at startup and injected
// into each reconciler rather than being threaded implicitly by the framework.
type Deps struct {
	Client   client.Client
	Settings *config.Settings
	// OIDC is nil when Settings.OidcProvider == "none" — deployments that
	// only ever use clienttype=spiffe ServiceAccounts. See requireOIDC.
	OIDC oidc.Provider
}
