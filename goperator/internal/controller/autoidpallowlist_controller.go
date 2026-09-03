package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	myceliamv1 "myceliam/api/v1"
	"myceliam/internal/models"
)

// allowlistObservedGenerationAnnotation is a pure trigger — its value is
// never read back, it only exists to cause a real object mutation (and
// therefore a watch event) on every autoidp=true ServiceAccount when the
// AutoidpAllowlist changes, so a newly-allowed namespace's SAs get
// provisioned promptly instead of waiting up to ReconcileIntervalSeconds for
// the periodic reconcile to notice. ServiceAccountReconciler.reconcile
// re-derives everything it needs (isNamespaceAllowed) fresh on every
// reconcile — it never reads this annotation's value.
const allowlistObservedGenerationAnnotation = "myceliam.io/allowlist-observed-resource-version"

// AutoidpAllowlistReconciler watches the singleton AutoidpAllowlist
// (myceliam-system/default) and, on change, pokes every autoidp=true
// ServiceAccount cluster-wide so it re-reconciles against the new list.
//
// Deliberately doesn't do anything for namespaces *removed* from the list —
// removing a namespace only stops future provisioning (enforced by
// requireNamespaceAllowed inside reconcileClient/reconcileCloud/
// reconcileSpiffe), it's never itself destructive to what's already
// provisioned; see AutoidpAllowlist's doc comment in api/v1. So there's
// nothing to actively clean up here, only newly-allowed namespaces benefit
// from the immediate poke.
type AutoidpAllowlistReconciler struct {
	Deps *Deps
}

func (r *AutoidpAllowlistReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Namespace != myceliamv1.AutoidpAllowlistNamespace || req.Name != myceliamv1.AutoidpAllowlistName {
		// Ignore anything but the one singleton instance this whole
		// reconciler cares about.
		return ctrl.Result{}, nil
	}

	var allowlist myceliamv1.AutoidpAllowlist
	if err := r.Deps.Client.Get(ctx, req.NamespacedName, &allowlist); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	selector, err := k8slabels.Parse(fmt.Sprintf("%s=true", models.AutoidpLabel))
	if err != nil {
		return ctrl.Result{}, err
	}
	var sas corev1.ServiceAccountList
	if err := r.Deps.Client.List(ctx, &sas, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return ctrl.Result{}, err
	}

	for i := range sas.Items {
		sa := &sas.Items[i]
		if sa.Annotations[allowlistObservedGenerationAnnotation] == allowlist.ResourceVersion {
			continue // already poked for this allowlist version, nothing to do
		}
		patch := client.MergeFrom(sa.DeepCopy())
		if sa.Annotations == nil {
			sa.Annotations = map[string]string{}
		}
		sa.Annotations[allowlistObservedGenerationAnnotation] = allowlist.ResourceVersion
		if err := r.Deps.Client.Patch(ctx, sa, patch); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *AutoidpAllowlistReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&myceliamv1.AutoidpAllowlist{}).
		Complete(r)
}
