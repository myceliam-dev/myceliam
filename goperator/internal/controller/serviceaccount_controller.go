package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"myceliam/internal/cloudmodels"
	"myceliam/internal/k8shelpers"
	"myceliam/internal/models"
)

// ServiceAccountReconciler ports handlers.py's reconcile_service_account,
// reconcile_service_account_periodically, and cleanup_service_account into a
// single Reconcile: a normal (non-deleting) pass does the same work
// reconcile_service_account did, and re-arms itself via ctrl.Result.RequeueAfter
// for the periodic drift-detection reconcile_service_account_periodically
// used to provide separately — see classify's doc comment.
type ServiceAccountReconciler struct {
	Deps *Deps
}

func (r *ServiceAccountReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var sa corev1.ServiceAccount
	if err := r.Deps.Client.Get(ctx, req.NamespacedName, &sa); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !sa.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&sa, finalizerName) {
			return ctrl.Result{}, nil
		}
		if err := r.cleanup(ctx, &sa); err != nil {
			return classify(ctx, err, 0)
		}
		controllerutil.RemoveFinalizer(&sa, finalizerName)
		if err := r.Deps.Client.Update(ctx, &sa); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&sa, finalizerName) {
		controllerutil.AddFinalizer(&sa, finalizerName)
		if err := r.Deps.Client.Update(ctx, &sa); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	oldLabels, oldAnnotations := readLastReconciledState(&sa)
	err := r.reconcile(ctx, &sa, oldLabels, oldAnnotations)
	if err == nil {
		if werr := writeLastReconciledState(ctx, r.Deps.Client, &sa); werr != nil {
			return ctrl.Result{}, werr
		}
	}

	periodicRequeue := time.Duration(r.Deps.Settings.ReconcileIntervalSeconds * float64(time.Second))
	return classify(ctx, err, periodicRequeue)
}

// reconcile is handlers.py's reconcile_service_account (also reachable, with
// oldLabels==labels so removedSpecs is always empty, as the periodic path —
// see the type doc comment above).
func (r *ServiceAccountReconciler) reconcile(ctx context.Context, sa *corev1.ServiceAccount, oldLabels, oldAnnotations map[string]string) error {
	namespace, name := sa.Namespace, sa.Name
	labels, annotations := sa.Labels, sa.Annotations

	if labels[models.ClientTypeLabel] == string(models.ClientTypeSpiffe) {
		oldJWTIssuer := oldAnnotations[models.SpiffeJWTIssuerAnnotation]
		newJWTIssuer := annotations[models.SpiffeJWTIssuerAnnotation]

		staleSpecs := removedSpecs(namespace, name, oldLabels, oldAnnotations, labels, annotations, r.Deps)
		if oldJWTIssuer != "" && oldJWTIssuer != newJWTIssuer {
			// The issuer itself changed (or was removed): every profile
			// registered under the old issuer is now orphaned there
			// regardless of whether its own label changed too.
			staleSpecs, _ = cloudmodels.ParseCloudFederationSpecs(namespace, name, oldLabels, oldAnnotations, r.Deps.Settings)
		}
		if len(staleSpecs) > 0 {
			if err := cleanupSpiffeSpecs(ctx, r.Deps, namespace, name, staleSpecs, oldJWTIssuer, oldAnnotations[models.SpiffeIDAnnotation]); err != nil {
				return err
			}
		}

		// Runs after cleanup so a removed/changed jwt-issuer annotation is
		// still cleaned up under the old issuer even though this call will
		// go on to fail for the SA's now-invalid (missing) annotation.
		return reconcileSpiffe(ctx, r.Deps, namespace, name, labels, annotations)
	}

	owner := k8shelpers.OwnerReference(sa)
	if err := reconcileClient(ctx, r.Deps, namespace, name, labels, owner); err != nil {
		return err
	}
	if err := reconcileCloud(ctx, r.Deps, namespace, name, labels, annotations); err != nil {
		return err
	}

	removed := removedSpecs(namespace, name, oldLabels, oldAnnotations, labels, annotations, r.Deps)
	if len(removed) > 0 {
		return cleanupCloud(ctx, r.Deps, namespace, name, removed)
	}
	return nil
}

// cleanup is handlers.py's cleanup_service_account.
func (r *ServiceAccountReconciler) cleanup(ctx context.Context, sa *corev1.ServiceAccount) error {
	namespace, name := sa.Namespace, sa.Name
	labels, annotations := sa.Labels, sa.Annotations

	if labels[models.ClientTypeLabel] == string(models.ClientTypeSpiffe) {
		return cleanupSpiffe(ctx, r.Deps, namespace, name, labels, annotations)
	}

	oidcProvider, err := requireOIDC(r.Deps, namespace, name)
	if err != nil {
		return err
	}
	if err := oidcProvider.DeleteClient(ctx, models.RealmForNamespace(namespace, r.Deps.Settings), name); err != nil {
		return err
	}
	// A parse error here (e.g. a profile label with no paired role
	// annotation) shouldn't block deletion — best-effort teardown of
	// whatever we can still identify, same reasoning as cleanupSpiffe.
	specs, _ := cloudmodels.ParseCloudFederationSpecs(namespace, name, labels, annotations, r.Deps.Settings)
	return cleanupCloud(ctx, r.Deps, namespace, name, specs)
}

func (r *ServiceAccountReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ServiceAccount{}, builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			return obj.GetLabels()[models.AutoidpLabel] == "true"
		}))).
		Complete(r)
}
