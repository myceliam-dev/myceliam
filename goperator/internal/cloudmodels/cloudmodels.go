// Package cloudmodels ports pythonoperator/src/myceliam/cloud_models.py: the
// AWS/GCP access-profile label constants and CloudFederationSpec derivation
// shared by every cloud-federation reconcile path (Keycloak-backed and spiffe).
package cloudmodels

import (
	"fmt"

	"myceliam/internal/config"
)

const (
	AwsProfileLabel = "myceliam.io/aws-access-profile"
	GcpProfileLabel = "myceliam.io/gcp-access-profile"
)

type CloudFederationSpec struct {
	Cloud       string // "aws" or "gcp"
	ProfileName string
	SAName      string
	ScopeName   string
	Audience    string
}

// ParseCloudFederationSpecs derives the desired cloud-federation state from a
// ServiceAccount's labels.
//
// Returns one CloudFederationSpec per cloud the SA has opted into (0, 1, or 2 —
// AwsProfileLabel and GcpProfileLabel are independent and each optional). A SA
// opting into a profile is granted trust/impersonation on *every* IAM role
// (aws) or service account email (gcp) listed across *every* account/project
// in the referenced AwsAccessProfile/GcpAccessProfile — there is no per-SA
// role selection; an admin who wants a SA to get a different, narrower, or
// wider set of grants creates a separate AccessProfile for it instead.
//
// Audience is deliberately cloud-specific, not shared, and follows a common
// "<cloud>-<namespace>[-<sa>]" shape:
//   - aws uses "aws-<namespace>-<sa>" — unique per SA, so a caller requesting
//     only the aws scope gets a single-value aud that by itself proves which
//     SA it is. This matters because AWS's OIDC federation folds azp into its
//     `:aud` policy-context key whenever the raw aud claim is a JSON array
//     (see aws.EnsureRoleTrust's own doc comment) — with a *shared* audience,
//     the single-value case would let any SA's token satisfy any other SA's
//     trust statement just by matching the common audience, with no
//     per-entity check at all. Making audience itself per-SA-unique closes
//     that regardless of which shape a given token ends up in.
//   - gcp uses "gcp-<namespace>" — shared across every SA in the namespace,
//     not per-SA. GCP's identity-scoping never came from aud in the first
//     place — the WLI provider's attributeMapping maps google.subject from
//     assertion.azp, and the actual grant is the per-SA workloadIdentityUser
//     binding scoped to that specific principal. aud there is only a
//     provider-level admission check (GCP natively accepts any match in a
//     multi-valued aud), so keeping it shared avoids turning the WLI
//     provider's allowedAudiences into a per-SA-growing list the way AWS's
//     ClientIDList already is.
func ParseCloudFederationSpecs(namespace, saName string, labels, annotations map[string]string, settings *config.Settings) ([]CloudFederationSpec, error) {
	type cloudLabel struct {
		cloud    string
		labelKey string
	}
	var specs []CloudFederationSpec
	for _, cl := range []cloudLabel{
		{"aws", AwsProfileLabel},
		{"gcp", GcpProfileLabel},
	} {
		profileName, ok := labels[cl.labelKey]
		if !ok || profileName == "" {
			continue
		}
		// Deliberately independent of profileName — a Keycloak client scope
		// is a per-(cloud, SA) thing, not a per-profile-object thing (an SA
		// can only ever reference one AwsAccessProfile/GcpAccessProfile at a
		// time via its single-value label, so there's no ambiguity to
		// disambiguate by including the profile's own name), and deriving it
		// from an admin's arbitrary profile-object name would make the scope
		// name only *coincidentally* consistent with the <cloud>-<namespace>
		// audience convention above rather than actually guaranteed by it.
		scopeName := fmt.Sprintf("%s-%s-%s", cl.cloud, namespace, saName)
		audience := scopeName
		if cl.cloud == "gcp" {
			audience = fmt.Sprintf("gcp-%s", namespace)
		}
		specs = append(specs, CloudFederationSpec{
			Cloud:       cl.cloud,
			ProfileName: profileName,
			SAName:      saName,
			ScopeName:   scopeName,
			Audience:    audience,
		})
	}
	return specs, nil
}
