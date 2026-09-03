package controller

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	myceliamv1 "myceliam/api/v1"
	"myceliam/internal/operr"
)

const allowlistCallDelay = 15 * time.Second

// isNamespaceAllowed reads the singleton AutoidpAllowlist
// (myceliam-system/default) and reports whether namespace may be
// provisioned. Absent entirely means every namespace is allowed — see
// AutoidpAllowlist's doc comment in api/v1 for why that's the deliberate
// zero-config default rather than fail-closed.
func isNamespaceAllowed(ctx context.Context, deps *Deps, namespace string) (bool, error) {
	var allowlist myceliamv1.AutoidpAllowlist
	err := deps.Client.Get(ctx, client.ObjectKey{
		Namespace: myceliamv1.AutoidpAllowlistNamespace,
		Name:      myceliamv1.AutoidpAllowlistName,
	}, &allowlist)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, operr.Temporaryf(allowlistCallDelay, "Error reading AutoidpAllowlist %s/%s: %v",
			myceliamv1.AutoidpAllowlistNamespace, myceliamv1.AutoidpAllowlistName, err)
	}
	for _, ns := range allowlist.Namespaces {
		if ns == namespace {
			return true, nil
		}
	}
	return false, nil
}

// requireNamespaceAllowed gates a *provisioning* operation on the allowlist —
// never call this from a cleanup/delete path (removing a namespace from the
// allowlist must not become destructive to whatever it already had
// provisioned; see AutoidpAllowlist's doc comment).
func requireNamespaceAllowed(ctx context.Context, deps *Deps, namespace, saName string) error {
	allowed, err := isNamespaceAllowed(ctx, deps, namespace)
	if err != nil {
		return err
	}
	if !allowed {
		return operr.Permanentf(
			"namespace '%s' is not listed in AutoidpAllowlist %s/%s; ServiceAccount '%s/%s' "+
				"will not be provisioned until it's added",
			namespace, myceliamv1.AutoidpAllowlistNamespace, myceliamv1.AutoidpAllowlistName, namespace, saName,
		)
	}
	return nil
}
