package controller

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"myceliam/internal/k8shelpers"
	"myceliam/internal/models"
)

// SecretReconciler ports handlers.py's reconcile_credentials_secret: cert
// rotation for signedjwt clients. If <sa-name>-oidc-credentials' tls.crt is
// edited (rotated), re-derive the JWKS and re-upload it. This same secret
// name is also used for clienttype=secret's own output, so this no-ops for
// those — it also fires (harmlessly) from the operator's own periodic writes
// to that secret.
//
// No finalizer: unlike ServiceAccount/Namespace/AccessProfile, this handler
// has no delete-time cleanup of its own (kopf's original is an
// @kopf.on.update handler only).
type SecretReconciler struct {
	Deps *Deps
}

func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	saName, ok := owningSAName(req.Name, r.Deps)
	if !ok {
		return ctrl.Result{}, nil
	}

	var sa corev1.ServiceAccount
	if err := r.Deps.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: saName}, &sa); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil // ServiceAccount gone; nothing to reconcile
		}
		return ctrl.Result{}, err
	}

	if sa.Labels[models.AutoidpLabel] != "true" || sa.Labels[models.ClientTypeLabel] != string(models.ClientTypeSignedJWT) {
		return ctrl.Result{}, nil
	}

	owner := k8shelpers.OwnerReference(&sa)
	err := reconcileClient(ctx, r.Deps, req.Namespace, saName, sa.Labels, owner)
	return classify(ctx, err, 0)
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	suffix := r.Deps.Settings.CredentialsSecretSuffix
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}, builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			return strings.HasSuffix(obj.GetName(), suffix)
		}))).
		Complete(r)
}
