package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	myceliamv1 "myceliam/api/v1"
	"myceliam/internal/cloudmodels"
	cloudaws "myceliam/internal/cloudproviders/aws"
	"myceliam/internal/models"
	"myceliam/internal/operatoridentity"
)

// AwsAccessProfileReconciler ports handlers.py's reconcile_aws_access_profile
// and cleanup_aws_access_profile.
//
// Unlike GCP's pool, there's no realm-independent setup to do here on
// create/update: an IAM OIDC provider's ARN embeds the namespace's realm
// issuer URL, so it can't be created before that realm exists — and the
// realm only ever comes into being when a ServiceAccount is reconciled. A
// profile with no referencing ServiceAccount yet has no realm to point an IdP
// at, so create/update just re-reconciles whichever ServiceAccounts already
// reference it (refreshServiceAccountsForProfile); provisioning the actual
// IdP is entirely reconcileCloud's job, which only ever runs after that SA's
// own realm+client already exist.
type AwsAccessProfileReconciler struct {
	Deps *Deps
}

func (r *AwsAccessProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var profile myceliamv1.AwsAccessProfile
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

	err := refreshServiceAccountsForProfile(ctx, r.Deps, profile.Namespace, cloudmodels.AwsProfileLabel, profile.Name)
	return classify(ctx, err, 0)
}

// cleanup is handlers.py's cleanup_aws_access_profile: deregisters the IAM
// OIDC provider in every account this profile listed. No-op when
// Deps.OIDC is nil (MYCELIAM_OIDC_PROVIDER=none) — this only ever cleans up
// the Keycloak-realm-issuer IdP; a spiffe-only deployment never registered
// one in the first place (spiffe federation goes through cleanupSpiffeSpecs
// instead, entirely independent of Deps.OIDC).
//
// Deliberately doesn't also strip each listed role's individual trust-policy
// statements here — that's cleanupCloud/cleanupSpiffeSpecs's job, fired
// per-entity as each referencing ServiceAccount is itself deleted, since only
// they know which specific entity to remove. Once the IdP itself is deleted,
// any leftover role-trust statement referencing it is permanently unmatchable
// anyway (its Federated principal ARN no longer resolves to anything), so
// this is a cleanliness gap, not a security one.
func (r *AwsAccessProfileReconciler) cleanup(ctx context.Context, profile *myceliamv1.AwsAccessProfile) error {
	if r.Deps.OIDC == nil {
		return nil
	}
	issuerURL, err := r.Deps.OIDC.IssuerURL(models.RealmForNamespace(profile.Namespace, r.Deps.Settings))
	if err != nil {
		return err
	}
	for accountID := range profile.Accounts {
		creds, err := operatoridentity.GetAWSCredentials(ctx, r.Deps.Settings, accountID, r.Deps.OIDC)
		if err != nil {
			return err
		}
		if err := cloudaws.DeleteIdp(ctx, accountID, issuerURL, creds); err != nil {
			return err
		}
	}
	return nil
}

func (r *AwsAccessProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&myceliamv1.AwsAccessProfile{}).
		Complete(r)
}
