package controller

import (
	"context"
	"encoding/json"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"myceliam/internal/cloudmodels"
	"myceliam/internal/models"
)

// lastReconciledAnnotation stamps a ServiceAccount with the subset of its own
// labels/annotations that reconcileServiceAccount's cleanup diffing cares
// about, once a reconcile of it succeeds — the Go equivalent of kopf's own
// kopf.zalando.org/last-handled-configuration annotation, which is exactly
// how kopf itself derives "old" for @kopf.on.update handlers (kopf has no
// magic memory of prior state either; it reads this same kind of annotation
// back off the object). Scoped to just the four fields handlers.py's diffing
// ever reads, rather than the whole object, so it doesn't churn on unrelated
// label/annotation changes.
const lastReconciledAnnotation = "myceliam.io/last-reconciled-state"

type reconciledState struct {
	ClientType      string `json:"clientType,omitempty"`
	AwsProfile      string `json:"awsProfile,omitempty"`
	GcpProfile      string `json:"gcpProfile,omitempty"`
	SpiffeJWTIssuer string `json:"spiffeJwtIssuer,omitempty"`
}

func stateFromLabels(labels, annotations map[string]string) reconciledState {
	return reconciledState{
		ClientType:      labels[models.ClientTypeLabel],
		AwsProfile:      labels[cloudmodels.AwsProfileLabel],
		GcpProfile:      labels[cloudmodels.GcpProfileLabel],
		SpiffeJWTIssuer: annotations[models.SpiffeJWTIssuerAnnotation],
	}
}

func (s reconciledState) toLabelsAndAnnotations() (labels, annotations map[string]string) {
	labels = map[string]string{}
	if s.ClientType != "" {
		labels[models.ClientTypeLabel] = s.ClientType
	}
	if s.AwsProfile != "" {
		labels[cloudmodels.AwsProfileLabel] = s.AwsProfile
	}
	if s.GcpProfile != "" {
		labels[cloudmodels.GcpProfileLabel] = s.GcpProfile
	}
	annotations = map[string]string{}
	if s.SpiffeJWTIssuer != "" {
		annotations[models.SpiffeJWTIssuerAnnotation] = s.SpiffeJWTIssuer
	}
	return labels, annotations
}

// readLastReconciledState returns the labels/annotations subset as of the
// last successful reconcile, or two empty maps if this is effectively a
// "create" (no prior state recorded) — matching reconcile_service_account's
// old=None-on-create case, where every diff against old_labels={} finds
// nothing removed.
func readLastReconciledState(sa *corev1.ServiceAccount) (labels, annotations map[string]string) {
	raw, ok := sa.Annotations[lastReconciledAnnotation]
	if !ok {
		return map[string]string{}, map[string]string{}
	}
	var state reconciledState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return map[string]string{}, map[string]string{}
	}
	return state.toLabelsAndAnnotations()
}

// writeLastReconciledState persists the current labels/annotations subset
// after a successful reconcile. No-op (no API call) if unchanged, so a
// periodic re-reconcile with no real drift never writes anything.
func writeLastReconciledState(ctx context.Context, c client.Client, sa *corev1.ServiceAccount) error {
	state := stateFromLabels(sa.Labels, sa.Annotations)
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if sa.Annotations != nil && sa.Annotations[lastReconciledAnnotation] == string(encoded) {
		return nil
	}

	patch := client.MergeFrom(sa.DeepCopy())
	if sa.Annotations == nil {
		sa.Annotations = map[string]string{}
	}
	sa.Annotations[lastReconciledAnnotation] = string(encoded)
	return c.Patch(ctx, sa, patch)
}
