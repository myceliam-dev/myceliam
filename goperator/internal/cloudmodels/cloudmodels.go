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

	// Auth0ServiceAccountClaim is the custom claim myceliam's tenant-wide
	// Auth0 Action (see internal/oidc/auth0's package doc comment) injects
	// into every issued access token, carrying the same bare-SA-name value
	// Keycloak's azp already carries. Auth0 itself doesn't support a custom
	// client_id, so unlike azp its own identity claims aren't predictable
	// until after the Application is created — this claim is self-issued
	// instead, restoring the same "known upfront" property Keycloak has.
	//
	// Not URI-namespaced (e.g. "https://myceliam.io/service_account"):
	// despite Auth0's own docs/examples recommending URI namespacing for
	// custom claims "to avoid collisions", it's just a convention, not
	// enforced — confirmed live against a real tenant, a plain
	// "myceliam_service_account" claim comes through in the issued token
	// exactly as set, no validation error.
	Auth0ServiceAccountClaim = "myceliam_service_account"
)

type CloudFederationSpec struct {
	Cloud       string // "aws" or "gcp"
	ProfileName string
	SAName      string
	ScopeName   string
	Audience    string

	// SharedAudience is true when Audience is shared across every SA in the
	// namespace requesting this cloud, rather than unique to this one SA.
	// True for every cloud under Auth0 (see below); for Keycloak, true only
	// for gcp. Threaded into cloudaws.EnsureRoleTrust so it can require a
	// strict aud+subjectClaim match instead of the weaker aud-alone
	// ForAnyValue match that's only safe when Audience is already
	// per-SA-unique.
	SharedAudience bool

	// SubjectClaim is which token claim carries the client's own identity —
	// see OidcSubjectClaim's doc comment. Threaded into
	// cloudaws.EnsureRoleTrust/RemoveRoleTrust in place of a hardcoded "azp"
	// literal.
	SubjectClaim string

	// SubjectClaimViaSessionTag is true when SubjectClaim isn't directly
	// usable as an AWS trust-policy condition key in its own right — Auth0's
	// case: confirmed live that a StringEquals condition on
	// "<provider>:myceliam_service_account" never matches, even with the
	// exact right value present in the JWT (AWS likely only exposes claims
	// declared in the provider's own OIDC discovery document, which never
	// lists one injected at runtime by an Action), while the identical claim
	// DOES work once also projected into the "https://aws.amazon.com/tags"
	// session-tags claim and matched via "aws:RequestTag/<SubjectClaim>"
	// instead (myceliam's tenant-wide Auth0 Action already emits this
	// claim — see internal/oidc/auth0's actionScript). Threaded into
	// cloudaws.EnsureRoleTrust so it knows which condition-key shape to
	// write. False for every other provider (Keycloak's azp and SPIFFE's sub
	// are both standard/discoverable claims that work directly).
	SubjectClaimViaSessionTag bool

	// IssuerShared is true when this provider's issuer is not exclusive to
	// this one namespace — Auth0's case: its issuer is the tenant's fixed
	// domain (see auth0.Provider.IssuerURL, which ignores tenantID
	// entirely), shared by every namespace/cluster using that same Auth0
	// tenant, and by the operator's own bootstrap identity too whenever it
	// shares the same AWS account. Keycloak's issuer is always
	// namespace(+cluster)-scoped by construction, so a namespace-local
	// "does any sibling ServiceAccount still need this" check is sufficient
	// there. Confirmed live as a real failure mode: cleanupCloud fully
	// deleted the shared AWS IAM OIDC provider for an Auth0 tenant once the
	// last Auth0-backed AWS ServiceAccount in ONE namespace went away,
	// silently breaking every other namespace on that tenant (and the
	// operator's own bootstrap trust, sharing the same account). Threaded
	// into cleanupCloud so it only ever calls cloudaws.RemoveAudience (this
	// one SA's ClientIDList entry) for a shared issuer, never
	// cloudaws.DeleteIdp (the whole provider) — mirroring how SPIFFE's own
	// cleanup, whose issuer is also typically shared cluster-wide, has
	// always worked.
	IssuerShared bool
}

// OidcSubjectClaim returns which claim an OIDC-issued token (as opposed to a
// SPIFFE JWT-SVID, which always uses "sub" independent of this function)
// carries the client's own identity under: "azp" for Keycloak, which always
// sets azp to the client_id, or Auth0ServiceAccountClaim for Auth0 (which
// has no custom-client_id support, so its own identity claims aren't
// predictable the way Keycloak's are — see that constant's own doc comment).
func OidcSubjectClaim(provider string) string {
	switch provider {
	case "auth0":
		return Auth0ServiceAccountClaim
	default:
		return "azp"
	}
}

// usesSharedAudience reports whether provider requires the namespace-shared,
// cluster-ID-folded audience convention (see ParseCloudFederationSpecs's own
// doc comment) rather than Keycloak's per-SA-unique one — true for any
// provider whose per-(cloud,namespace) resource isn't cheap/unlimited to
// create the way a Keycloak client scope is. True for Auth0 APIs today.
func usesSharedAudience(provider string) bool {
	return provider == "auth0"
}

// subjectClaimViaSessionTag reports whether provider's SubjectClaim needs
// the AWS session-tags detour described on CloudFederationSpec's own field
// doc comment rather than a direct "<issuer>:<claim>" trust-policy
// condition. True only for Auth0 today.
func subjectClaimViaSessionTag(provider string) bool {
	return provider == "auth0"
}

// IssuerSharedAcrossNamespaces reports whether provider's issuer is shared
// beyond the one namespace being reconciled — see
// CloudFederationSpec.IssuerShared's own doc comment. True only for Auth0
// today.
func IssuerSharedAcrossNamespaces(provider string) bool {
	return provider == "auth0"
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
//
// Under usesSharedAudience(provider) (Auth0) this convention changes for
// BOTH clouds: an Auth0 API holds exactly one fixed aud (unlike a Keycloak
// client scope, which is cheap/unlimited per-SA), so audiences are always
// namespace-shared, never per-SA. Auth0 has no realm-like boundary to
// implicitly carry cluster scoping the way a Keycloak realm does (every
// cluster shares one flat tenant), so the cluster ID is folded into the
// audience string explicitly here instead: "<cloud>-<cluster-id>-<namespace>".
// Per-SA discrimination beyond the shared audience is intended to come from
// SubjectClaim in whatever Condition an account owner writes on the IAM
// role's trust policy / GCP WLI provider's attribute condition — myceliam
// itself never builds that Condition (registration-only: aws.go only
// manages ClientIDList; gcp.go is the one place SubjectClaim actually gets
// wired into a real attribute condition, confirmed working live). For Auth0
// this is Auth0ServiceAccountClaim, self-issued via a tenant-wide Action
// rather than relying on Auth0's own identity claims (see
// internal/oidc/auth0's package doc comment for why).
//
// AWS's AssumeRoleWithWebIdentity trust-policy CONDITION cannot reference a
// custom claim like myceliam_service_account directly (confirmed
// empirically): a StringEquals condition on
// "<provider>:myceliam_service_account" never matches even with the exact
// right value present in the JWT, while :sub/:aud conditions against the
// identical token work fine — AWS likely only exposes claims declared in the
// provider's own OIDC discovery document (claims_supported), which never
// lists a claim injected at runtime by an Action.
//
// There IS a real, working AWS-native path around this, though — confirmed
// live end to end (a Deny keyed on the tag actually blocked an otherwise
// broadly-permitted S3 call): AWS's session-tags-via-AssumeRoleWithWebIdentity
// feature (IAM User Guide, "Pass session tags in AWS STS"). If the Action
// also sets a claim named exactly "https://aws.amazon.com/tags" shaped as
// {"principal_tags": {"myceliam_service_account": ["sa1"], "myceliam_namespace":
// ["ns1"], "myceliam_cluster_id": ["id1"], "myceliam_cloud": ["gcp,aws"]}}
// (all four claims this package already sets on client_metadata map
// cleanly this way, confirmed live, not just service_account) — each
// principal_tags array MUST hold exactly one string (myceliam_cloud's
// comma-joined "gcp,aws" is fine, still one string; a genuine multi-element
// array is not: confirmed live, AWS rejects the ENTIRE token outright with
// InvalidIdentityToken: "Claim <name> contains invalid value for
// principal_tags" — it does not pick an index or otherwise degrade
// gracefully), and the IAM role's trust policy additionally allows the
// sts:TagSession action (on top of sts:AssumeRoleWithWebIdentity) for that
// Federated principal, AWS applies myceliam_service_account as a genuine
// IAM principal tag, matchable via aws:RequestTag/myceliam_service_account
// on the role's OWN trust-policy Condition, gating the
// AssumeRoleWithWebIdentity call itself (confirmed live: matching value
// succeeds, mismatched value fails the assumption outright with
// AccessDenied). This restores real per-SA discrimination for AWS despite
// one shared Auth0 Application per namespace.
//
// Implemented end to end: internal/oidc/auth0's Action (see actions.go's
// actionScript) emits the https://aws.amazon.com/tags claim automatically
// alongside the plain claims; SubjectClaimViaSessionTag (set true for Auth0
// by subjectClaimViaSessionTag below) tells cloudaws.EnsureRoleTrust to grant
// sts:TagSession and write the aws:RequestTag/<SubjectClaim> condition
// instead of a plain "<issuer>:<SubjectClaim>" one that would never match.
// This does NOT affect GCP (confirmed live: an
// assertion.myceliam_service_account attribute condition already succeeds
// there directly, no session-tags detour needed).
func ParseCloudFederationSpecs(namespace, saName string, labels, annotations map[string]string, provider string, settings *config.Settings) ([]CloudFederationSpec, error) {
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

		var scopeName, audience string
		sharedAudience := cl.cloud == "gcp"
		if usesSharedAudience(provider) {
			// One API (Auth0) per (cloud, cluster, namespace) — see the
			// package doc comment above.
			// scopeName has no separate meaning here (no client-scope-like
			// object to name), so it's just set equal to audience.
			audience = fmt.Sprintf("%s-%s-%s", cl.cloud, settings.ClusterID, namespace)
			scopeName = audience
			sharedAudience = true
		} else {
			// Deliberately independent of profileName — a Keycloak client
			// scope is a per-(cloud, SA) thing, not a per-profile-object
			// thing (an SA can only ever reference one
			// AwsAccessProfile/GcpAccessProfile at a time via its
			// single-value label, so there's no ambiguity to disambiguate by
			// including the profile's own name), and deriving it from an
			// admin's arbitrary profile-object name would make the scope
			// name only *coincidentally* consistent with the
			// <cloud>-<namespace> audience convention above rather than
			// actually guaranteed by it.
			scopeName = fmt.Sprintf("%s-%s-%s", cl.cloud, namespace, saName)
			audience = scopeName
			if cl.cloud == "gcp" {
				audience = fmt.Sprintf("gcp-%s", namespace)
			}
		}

		specs = append(specs, CloudFederationSpec{
			Cloud:                     cl.cloud,
			ProfileName:               profileName,
			SAName:                    saName,
			ScopeName:                 scopeName,
			Audience:                  audience,
			SharedAudience:            sharedAudience,
			SubjectClaim:              OidcSubjectClaim(provider),
			SubjectClaimViaSessionTag: subjectClaimViaSessionTag(provider),
			IssuerShared:              IssuerSharedAcrossNamespaces(provider),
		})
	}
	return specs, nil
}
