package controller

import (
	"context"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"myceliam/internal/operr"
)

// classify turns a reconcile error into a ctrl.Result the way kopf turns
// TemporaryError/PermanentError into its own retry scheduling:
//
//   - nil error, and periodicRequeue > 0: mirrors reconcile_service_account
//     also being reachable from @kopf.on.timer — every successful reconcile
//     re-arms itself for periodic drift detection (Keycloak/cloud-side
//     changes with no Kubernetes-side event), not just react-to-change.
//   - *operr.Temporary: requeue after its own Delay, exactly like
//     kopf.TemporaryError(delay=N) — deliberately NOT returned as a Go error,
//     since that would additionally trigger controller-runtime's own
//     exponential-backoff requeue on top of the explicit delay.
//   - *operr.Permanent: logged, and (if periodicRequeue > 0) still re-armed
//     on the periodic schedule — matching kopf's behavior where a
//     PermanentError from @kopf.on.timer doesn't disable the timer, it just
//     fails that one firing; the next periodic firing is a fresh attempt.
//     Also not returned as a Go error, for the same reason as Temporary.
//   - anything else: returned as-is, so controller-runtime's default
//     exponential-backoff retry applies — the same fallback kopf itself uses
//     for an unrecognized exception type.
func classify(ctx context.Context, err error, periodicRequeue time.Duration) (ctrl.Result, error) {
	if err == nil {
		if periodicRequeue > 0 {
			return ctrl.Result{RequeueAfter: periodicRequeue}, nil
		}
		return ctrl.Result{}, nil
	}
	if temp, ok := operr.AsTemporary(err); ok {
		log.FromContext(ctx).Info("temporary reconcile error; will retry", "error", temp.Error(), "delay", temp.Delay)
		return ctrl.Result{RequeueAfter: temp.Delay}, nil
	}
	if perm, ok := operr.AsPermanent(err); ok {
		log.FromContext(ctx).Error(perm, "permanent reconcile error; will not retry until next change or periodic reconcile")
		if periodicRequeue > 0 {
			return ctrl.Result{RequeueAfter: periodicRequeue}, nil
		}
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, err
}
