package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	myceliamv1 "myceliam/api/v1"
	"myceliam/internal/cloudmodels"
	cloudgcp "myceliam/internal/cloudproviders/gcp"
)

// GcpAccessProfileReconciler ports handlers.py's reconcile_gcp_access_profile
// and cleanup_gcp_access_profile.
type GcpAccessProfileReconciler struct {
	Deps *Deps
}

func (r *GcpAccessProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var profile myceliamv1.GcpAccessProfile
	if err := r.Deps.Client.Get(ctx, req.NamespacedName, &profile); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !profile.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&profile, finalizerName) {
			return ctrl.Result{}, nil
		}
		if err := r.cleanup(ctx, &profile); err != nil {
			return classify(ctx, err, 0)
		}
		controllerutil.RemoveFinalizer(&profile, finalizerName)
		if err := r.Deps.Client.Update(ctx, &profile); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&profile, finalizerName) {
		controllerutil.AddFinalizer(&profile, finalizerName)
		if err := r.Deps.Client.Update(ctx, &profile); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	for projectID := range profile.Projects {
		if err := cloudgcp.EnsurePool(ctx, projectID, r.Deps.Settings, r.Deps.OIDC); err != nil {
			return classify(ctx, err, 0)
		}
	}
	err := refreshServiceAccountsForProfile(ctx, r.Deps, profile.Namespace, cloudmodels.GcpProfileLabel, profile.Name)
	return classify(ctx, err, 0)
}

// cleanup is handlers.py's cleanup_gcp_access_profile: deregisters the
// Workload Identity Pool Provider(s) in every project this profile listed.
// Leaves the shared pool itself in place — it's shared across every
// namespace targeting the same project, not owned by this one profile.
//
// Deletes both the KindOIDC and KindSpiffe provider unconditionally rather
// than figuring out which kind(s) the namespace actually used — DeleteIdp
// already no-ops on 404, and by CR-delete time there's no reliable way to
// tell which kinds ever existed short of tracking it separately.
func (r *GcpAccessProfileReconciler) cleanup(ctx context.Context, profile *myceliamv1.GcpAccessProfile) error {
	for projectID := range profile.Projects {
		for _, kind := range []string{cloudgcp.KindOIDC, cloudgcp.KindSpiffe} {
			if err := cloudgcp.DeleteIdp(ctx, projectID, profile.Namespace, r.Deps.Settings, kind, r.Deps.OIDC); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *GcpAccessProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&myceliamv1.GcpAccessProfile{}).
		Complete(r)
}
