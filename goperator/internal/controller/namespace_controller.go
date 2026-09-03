package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"myceliam/internal/models"
)

// NamespaceReconciler ports handlers.py's cleanup_namespace: tears down the
// namespace's whole Keycloak realm once the namespace itself is deleted —
// unlike a single ServiceAccount going away, nothing can ever reference this
// realm again, so there's no "other SAs might still need it" reason to leave
// it behind.
//
// This watches (and adds its finalizer to) every namespace in the cluster,
// not just ones with myceliam ServiceAccounts — the same unfiltered
// @kopf.on.delete("", "v1", "namespaces") behavior the Python original
// already has. No-op if the namespace never had a realm (DeleteTenant is a
// no-op if the realm doesn't exist), and a further no-op entirely when
// Deps.OIDC is nil (MYCELIAM_OIDC_PROVIDER=none) since a spiffe-only
// deployment never registers a realm to begin with.
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
		if r.Deps.OIDC != nil {
			if err := r.Deps.OIDC.DeleteTenant(ctx, models.RealmForNamespace(ns.Name, r.Deps.Settings)); err != nil {
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
