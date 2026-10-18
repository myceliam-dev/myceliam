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
// OIDC provider in every account this profile listed. No-op when no OIDC
// provider is active at all — this only ever cleans up a Keycloak/Auth0
// realm-issuer IdP; a spiffe-only deployment never registered one in the
// first place (spiffe federation goes through cleanupSpiffeSpecs instead).
//
// By the time a profile has no referencing ServiceAccount left, there's no
// remaining signal for which OF the operator's (possibly several) active
// providers ever backed one — so this tries every active provider's own
// issuer URL for this namespace, not just one. DeleteIdp is a no-op for an
// issuer that was never actually registered (same idempotent-by-design
// pattern every other IdP-deletion call in this codebase follows), so
// harmlessly attempting issuers that were never used here costs nothing.
//
// Providers whose issuer isn't namespace-exclusive
// (cloudmodels.IssuerSharedAcrossNamespaces — Auth0) are skipped entirely
// here: this profile's own namespace never "owns" that shared IdP, only the
// individual ServiceAccounts that registered entries in its ClientIDList do
// (cleanupCloud, per-SA, via RemoveAudience) — confirmed live that calling
// DeleteIdp here for Auth0 deleted the tenant-wide provider out from under
// every other namespace on that tenant (and the operator's own bootstrap
// trust) the moment just this one profile went away. For the providers this
// still applies to, operatorClientIdentifiers is passed as a second line of
// defense against deleting the operator's own bootstrap identity too.
//
// Deliberately doesn't also strip each listed role's individual trust-policy
// statements here — that's cleanupCloud/cleanupSpiffeSpecs's job, fired
// per-entity as each referencing ServiceAccount is itself deleted, since only
// they know which specific entity to remove. Once the IdP itself is deleted,
// any leftover role-trust statement referencing it is permanently unmatchable
// anyway (its Federated principal ARN no longer resolves to anything), so
// this is a cleanliness gap, not a security one.
func (r *AwsAccessProfileReconciler) cleanup(ctx context.Context, profile *myceliamv1.AwsAccessProfile) error {
	type target struct {
		issuerURL    string
		protectedIDs []string
	}
	targets := make(map[string]target, len(r.Deps.OIDCProviders))
	for providerName, p := range r.Deps.OIDCProviders {
		if cloudmodels.IssuerSharedAcrossNamespaces(providerName) {
			continue
		}
		issuerURL, err := p.IssuerURL(models.RealmForNamespace(profile.Namespace, r.Deps.Settings))
		if err != nil {
			return err
		}
		targets[issuerURL] = target{issuerURL: issuerURL, protectedIDs: operatorClientIdentifiers(r.Deps, providerName)}
	}
	if len(targets) == 0 {
		return nil
	}
	for accountID := range profile.Accounts {
		creds, err := operatoridentity.GetAWSCredentials(ctx, r.Deps.Settings, accountID, r.Deps.OperatorOIDC)
		if err != nil {
			return err
		}
		for _, t := range targets {
			if err := cloudaws.DeleteIdp(ctx, accountID, t.issuerURL, t.protectedIDs, creds); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *AwsAccessProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&myceliamv1.AwsAccessProfile{}).
		Complete(r)
}
