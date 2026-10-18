package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"myceliam/internal/models"
)

// NamespaceReconciler ports handlers.py's cleanup_namespace: tears down
// every namespace-scoped OIDC resource once the namespace itself is deleted
// — unlike a single ServiceAccount going away, nothing can ever reference
// any of it again, so there's no "other SAs might still need it" reason to
// leave it behind. For Keycloak that's the whole realm (one call, cascades);
// for Auth0, which has no such single container, DeleteTenant instead
// force-sweeps the two shared per-(cloud,namespace) Resource Servers
// directly — see its own DeleteTenant doc comment for why that sweep exists
// at all (confirmed live: without it, a Resource Server can outlive every
// ServiceAccount that ever referenced it).
//
// This watches (and adds its finalizer to) every namespace in the cluster,
// not just ones with myceliam ServiceAccounts — the same unfiltered
// @kopf.on.delete("", "v1", "namespaces") behavior the Python original
// already has. By namespace-delete time there's no reliable way to tell
// which of the operator's (possibly several) active providers ever backed a
// realm/tenant here, so DeleteTenant is called on every one of them — each
// is documented as a no-op if it finds nothing to delete, so calling all of
// them costs nothing for the ones that were never used. A further no-op
// entirely when no OIDC provider is active at all (a spiffe-only deployment
// never registers a realm/tenant to begin with).
type NamespaceReconciler struct {
	Deps *Deps
}

func (r *NamespaceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ns corev1.Namespace
	if err := r.Deps.Client.Get(ctx, req.NamespacedName, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !ns.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&ns, finalizerName) {
			return ctrl.Result{}, nil
		}
		for _, p := range r.Deps.OIDCProviders {
			if err := p.DeleteTenant(ctx, models.RealmForNamespace(ns.Name, r.Deps.Settings)); err != nil {
				return classify(ctx, err, 0)
			}
		}
		controllerutil.RemoveFinalizer(&ns, finalizerName)
		if err := r.Deps.Client.Update(ctx, &ns); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&ns, finalizerName) {
		controllerutil.AddFinalizer(&ns, finalizerName)
		if err := r.Deps.Client.Update(ctx, &ns); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *NamespaceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Namespace{}).
		Complete(r)
}
