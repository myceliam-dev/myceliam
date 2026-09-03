package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8slabels "k8s.io/apimachinery/pkg/labels"

	myceliamv1 "myceliam/api/v1"
	"myceliam/internal/certgen"
	"myceliam/internal/cloudmodels"
	cloudaws "myceliam/internal/cloudproviders/aws"
	cloudgcp "myceliam/internal/cloudproviders/gcp"
	"myceliam/internal/jwks"
	"myceliam/internal/k8shelpers"
	"myceliam/internal/models"
	"myceliam/internal/oidc"
	"myceliam/internal/operatoridentity"
	"myceliam/internal/operr"
)

const profileWaitDelay = 20 * time.Second

// requireOIDC mirrors handlers.py's _require_oidc: secret/signedjwt SAs need
// an actual oidc.Provider — unlike spiffe, which never touches it at all.
// Only reachable at all when MYCELIAM_OIDC_PROVIDER=none was chosen
// deliberately (an unrecognized provider name fails fast at Settings
// construction; a recognized-but-unimplemented one fails fast at startup
// inside oidc.GetProvider) — so by the time any reconciler runs, deps.OIDC is
// only ever nil because "none" was chosen on purpose.
func requireOIDC(deps *Deps, namespace, name string) (oidc.Provider, error) {
	if deps.OIDC == nil {
		return nil, operr.Permanentf(
			"ServiceAccount '%s/%s' needs a Keycloak/Okta/Auth0-backed client "+
				"(clienttype=secret/signedjwt), but MYCELIAM_OIDC_PROVIDER is 'none' "+
				"— set it to 'keycloak' (or another supported provider) to use this client "+
				"type, or use clienttype=spiffe instead if this ServiceAccount doesn't need one.",
			namespace, name,
		)
	}
	return deps.OIDC, nil
}

// reconcileClient mirrors handlers.py's _reconcile: ensures the realm/client
// (and, for signedjwt, the keypair Secret + JWKS) for a secret/signedjwt
// ServiceAccount. Gated on the AutoidpAllowlist — see requireNamespaceAllowed.
func reconcileClient(ctx context.Context, deps *Deps, namespace, name string, labels map[string]string, owner metav1.OwnerReference) error {
	if err := requireNamespaceAllowed(ctx, deps, namespace, name); err != nil {
		return err
	}

	oidcProvider, err := requireOIDC(deps, namespace, name)
	if err != nil {
		return err
	}

	spec, err := models.ParseClientSpec(namespace, name, labels, deps.Settings)
	if err != nil {
		return err
	}
	if err := oidcProvider.EnsureTenant(ctx, spec.Realm); err != nil {
		return err
	}

	if spec.ClientType == models.ClientTypeSecret {
		clientID, clientSecret, err := oidcProvider.EnsureSecretClient(ctx, spec)
		if err != nil {
			return err
		}
		issuerURL, err := oidcProvider.IssuerURL(spec.Realm)
		if err != nil {
			return err
		}
		return k8shelpers.WriteCredentialsSecret(ctx, deps.Client, namespace, spec.CredentialsSecretName, map[string]string{
			"client_id":     clientID,
			"client_secret": clientSecret,
			"issuer":        issuerURL,
		}, owner)
	}

	certPEM, found, err := k8shelpers.ReadSecretKeyIfPresent(ctx, deps.Client, namespace, spec.CredentialsSecretName, corev1.TLSCertKey)
	if err != nil {
		return err
	}
	if !found {
		var keyPEM []byte
		certPEM, keyPEM, err = certgen.GenerateSelfSignedKeypair(spec.ClientName, deps.Settings.SignedjwtKeySize, deps.Settings.SignedjwtCertValidityDays)
		if err != nil {
			return err
		}
		if err := k8shelpers.CreateTLSSecretIfAbsent(ctx, deps.Client, namespace, spec.CredentialsSecretName, certPEM, keyPEM, owner); err != nil {
			return err
		}
	}
	jwksString, err := jwks.PemCertToJWKSString(certPEM)
	if err != nil {
		return err
	}
	_, err = oidcProvider.EnsureSignedjwtClient(ctx, spec, jwksString)
	return err
}

// reconcileCloud mirrors handlers.py's _reconcile_cloud, extended for C:
// federates the namespace's realm into every account/project listed in the
// AwsAccessProfile/GcpAccessProfile the SA opted into via
// AwsProfileLabel/GcpProfileLabel labels, AND manages trust/impersonation on
// *every* IAM role (aws) / service account email (gcp) that profile lists —
// there is no per-SA role selection; every SA referencing a given profile
// gets identical access to everything it lists. No-ops if neither label is
// present. Gated on the AutoidpAllowlist.
func reconcileCloud(ctx context.Context, deps *Deps, namespace, saName string, labels, annotations map[string]string) error {
	if err := requireNamespaceAllowed(ctx, deps, namespace, saName); err != nil {
		return err
	}

	specs, err := cloudmodels.ParseCloudFederationSpecs(namespace, saName, labels, annotations, deps.Settings)
	if err != nil {
		return err
	}
	if len(specs) == 0 {
		return nil
	}

	oidcProvider, err := requireOIDC(deps, namespace, saName)
	if err != nil {
		return err
	}
	issuerURL, err := oidcProvider.IssuerURL(models.RealmForNamespace(namespace, deps.Settings))
	if err != nil {
		return err
	}

	for _, spec := range specs {
		if err := oidcProvider.EnsureAccessScope(ctx, models.RealmForNamespace(namespace, deps.Settings), saName, spec.ScopeName, spec.Audience); err != nil {
			return err
		}

		if spec.Cloud == "aws" {
			var profile myceliamv1.AwsAccessProfile
			found, err := k8shelpers.ReadAccessProfile(ctx, deps.Client, namespace, spec.ProfileName, &profile)
			if err != nil {
				return err
			}
			if !found {
				return operr.Temporaryf(profileWaitDelay, "AwsAccessProfile '%s/%s' referenced by ServiceAccount '%s/%s' not found yet; will retry", namespace, spec.ProfileName, namespace, saName)
			}
			for accountID, roles := range profile.Accounts {
				creds, err := operatoridentity.GetAWSCredentials(ctx, deps.Settings, accountID, deps.OIDC)
				if err != nil {
					return err
				}
				if err := cloudaws.EnsureIdp(ctx, accountID, issuerURL, []string{spec.Audience, saName}, creds); err != nil {
					return err
				}
				for _, role := range roles {
					if err := cloudaws.EnsureRoleTrust(ctx, accountID, role, issuerURL, spec.Audience, "azp", saName, creds); err != nil {
						return err
					}
				}
			}
		} else {
			var profile myceliamv1.GcpAccessProfile
			found, err := k8shelpers.ReadAccessProfile(ctx, deps.Client, namespace, spec.ProfileName, &profile)
			if err != nil {
				return err
			}
			if !found {
				return operr.Temporaryf(profileWaitDelay, "GcpAccessProfile '%s/%s' referenced by ServiceAccount '%s/%s' not found yet; will retry", namespace, spec.ProfileName, namespace, saName)
			}
			for projectID, emails := range profile.Projects {
				if err := cloudgcp.EnsureIdp(ctx, projectID, namespace, issuerURL, spec.Audience, deps.Settings, cloudgcp.KindOIDC, deps.OIDC); err != nil {
					return err
				}
				for _, email := range emails {
					if err := cloudgcp.GrantImpersonation(ctx, email, projectID, saName, deps.Settings, deps.OIDC); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func siblingsStillActive(sas []corev1.ServiceAccount, excludeName string) bool {
	for _, sa := range sas {
		if sa.Name != excludeName && sa.DeletionTimestamp == nil {
			return true
		}
	}
	return false
}

// cleanupCloud mirrors handlers.py's _cleanup_cloud, extended for C: deletes
// the per-SA Keycloak client scope for each spec unconditionally, and revokes
// the SA's own role-trust/impersonation grant. What happens to the IdP/WLI
// provider itself then depends on whether any *other* secret/signedjwt
// ServiceAccount in the namespace still references the same profile. Never
// gated on the AutoidpAllowlist — cleanup must always be able to proceed
// regardless of a namespace's current allowlist status.
func cleanupCloud(ctx context.Context, deps *Deps, namespace, saName string, specs []cloudmodels.CloudFederationSpec) error {
	if len(specs) == 0 {
		return nil
	}
	oidcProvider, err := requireOIDC(deps, namespace, saName)
	if err != nil {
		return err
	}

	for _, spec := range specs {
		if err := oidcProvider.DeleteAccessScope(ctx, models.RealmForNamespace(namespace, deps.Settings), spec.ScopeName); err != nil {
			return err
		}

		labelKey := cloudmodels.AwsProfileLabel
		if spec.Cloud != "aws" {
			labelKey = cloudmodels.GcpProfileLabel
		}
		selector, err := k8slabels.Parse(fmt.Sprintf("%s=%s,%s!=%s", labelKey, spec.ProfileName, models.ClientTypeLabel, models.ClientTypeSpiffe))
		if err != nil {
			return err
		}
		siblings, err := k8shelpers.ListServiceAccountsByLabel(ctx, deps.Client, namespace, selector)
		if err != nil {
			return err
		}
		stillActive := siblingsStillActive(siblings, saName)

		if spec.Cloud == "aws" {
			var profile myceliamv1.AwsAccessProfile
			found, err := k8shelpers.ReadAccessProfile(ctx, deps.Client, namespace, spec.ProfileName, &profile)
			if err != nil {
				return err
			}
			if !found {
				continue
			}
			issuerURL, err := oidcProvider.IssuerURL(models.RealmForNamespace(namespace, deps.Settings))
			if err != nil {
				return err
			}
			for accountID, roles := range profile.Accounts {
				creds, err := operatoridentity.GetAWSCredentials(ctx, deps.Settings, accountID, deps.OIDC)
				if err != nil {
					return err
				}
				for _, role := range roles {
					if err := cloudaws.RemoveRoleTrust(ctx, accountID, role, issuerURL, "azp", saName, creds); err != nil {
						return err
					}
				}
				if stillActive {
					err = cloudaws.RemoveAudience(ctx, accountID, issuerURL, saName, creds)
				} else {
					err = cloudaws.DeleteIdp(ctx, accountID, issuerURL, creds)
				}
				if err != nil {
					return err
				}
			}
		} else {
			var profile myceliamv1.GcpAccessProfile
			found, err := k8shelpers.ReadAccessProfile(ctx, deps.Client, namespace, spec.ProfileName, &profile)
			if err != nil {
				return err
			}
			if !found {
				continue
			}
			for projectID, emails := range profile.Projects {
				for _, email := range emails {
					if err := cloudgcp.RevokeImpersonation(ctx, email, projectID, saName, deps.Settings, deps.OIDC); err != nil {
						return err
					}
				}
				if !stillActive {
					if err := cloudgcp.DeleteIdp(ctx, projectID, namespace, deps.Settings, cloudgcp.KindOIDC, deps.OIDC); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// reconcileSpiffe mirrors handlers.py's _reconcile_spiffe, extended for C:
// federates a SPIFFE-issued identity into every account/project the SA
// opted into, using the SPIRE OIDC Discovery Provider named in
// annotations[SpiffeJWTIssuerAnnotation] as the IdP's issuer, and manages
// trust/impersonation on *every* role/service-account those profiles list,
// scoped to this SA's own annotations[SpiffeIDAnnotation] (required whenever
// a cloud federation label is present — see models.SpiffeIDAnnotation's doc
// comment for why SPIFFE can't reuse the SA-name-based azp narrowing
// Keycloak-issued tokens get). There is no Keycloak realm/client/scope/
// credentials Secret involved at all for this client type. Gated on the
// AutoidpAllowlist.
func reconcileSpiffe(ctx context.Context, deps *Deps, namespace, saName string, labels, annotations map[string]string) error {
	if err := requireNamespaceAllowed(ctx, deps, namespace, saName); err != nil {
		return err
	}

	jwtIssuer := annotations[models.SpiffeJWTIssuerAnnotation]
	if jwtIssuer == "" {
		return operr.Permanentf(
			"ServiceAccount '%s/%s' has label '%s=%s' but is missing the '%s' annotation.",
			namespace, saName, models.ClientTypeLabel, models.ClientTypeSpiffe, models.SpiffeJWTIssuerAnnotation,
		)
	}

	specs, err := cloudmodels.ParseCloudFederationSpecs(namespace, saName, labels, annotations, deps.Settings)
	if err != nil {
		return err
	}
	if len(specs) == 0 {
		return nil
	}

	spiffeID := annotations[models.SpiffeIDAnnotation]
	if spiffeID == "" {
		return operr.Permanentf(
			"ServiceAccount '%s/%s' requests cloud federation but is missing the '%s' annotation "+
				"(needed to scope role trust/impersonation to this specific SPIFFE identity).",
			namespace, saName, models.SpiffeIDAnnotation,
		)
	}

	for _, spec := range specs {
		if spec.Cloud == "aws" {
			var profile myceliamv1.AwsAccessProfile
			found, err := k8shelpers.ReadAccessProfile(ctx, deps.Client, namespace, spec.ProfileName, &profile)
			if err != nil {
				return err
			}
			if !found {
				return operr.Temporaryf(profileWaitDelay, "AwsAccessProfile '%s/%s' referenced by ServiceAccount '%s/%s' not found yet; will retry", namespace, spec.ProfileName, namespace, saName)
			}
			for accountID, roles := range profile.Accounts {
				creds, err := operatoridentity.GetAWSCredentials(ctx, deps.Settings, accountID, deps.OIDC)
				if err != nil {
					return err
				}
				if err := cloudaws.EnsureIdp(ctx, accountID, jwtIssuer, []string{spec.Audience}, creds); err != nil {
					return err
				}
				for _, role := range roles {
					if err := cloudaws.EnsureRoleTrust(ctx, accountID, role, jwtIssuer, spec.Audience, "sub", spiffeID, creds); err != nil {
						return err
					}
				}
			}
		} else {
			var profile myceliamv1.GcpAccessProfile
			found, err := k8shelpers.ReadAccessProfile(ctx, deps.Client, namespace, spec.ProfileName, &profile)
			if err != nil {
				return err
			}
			if !found {
				return operr.Temporaryf(profileWaitDelay, "GcpAccessProfile '%s/%s' referenced by ServiceAccount '%s/%s' not found yet; will retry", namespace, spec.ProfileName, namespace, saName)
			}
			for projectID, emails := range profile.Projects {
				if err := cloudgcp.EnsureIdp(ctx, projectID, namespace, jwtIssuer, spec.Audience, deps.Settings, cloudgcp.KindSpiffe, deps.OIDC); err != nil {
					return err
				}
				for _, email := range emails {
					if err := cloudgcp.GrantImpersonation(ctx, email, projectID, spiffeID, deps.Settings, deps.OIDC); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// cleanupSpiffeSpecs mirrors handlers.py's _cleanup_spiffe_specs, extended
// for C: core of spiffe cloud-federation teardown, shared by full SA deletion
// and a label/annotation change while the SA is still otherwise active. A
// given spec is only actually torn down once no *other* spiffe SA in the
// namespace still references the same profile. spiffeID may be empty (e.g.
// the annotation was removed along with the profile label) — role-trust
// revocation is skipped in that case, since there's nothing to compute the
// statement/member identifier from; the IdP/provider-level teardown below
// still proceeds independent of that.
func cleanupSpiffeSpecs(ctx context.Context, deps *Deps, namespace, saName string, specs []cloudmodels.CloudFederationSpec, jwtIssuer, spiffeID string) error {
	if jwtIssuer == "" {
		return nil
	}

	for _, spec := range specs {
		labelKey := cloudmodels.AwsProfileLabel
		if spec.Cloud != "aws" {
			labelKey = cloudmodels.GcpProfileLabel
		}
		selector, err := k8slabels.Parse(fmt.Sprintf("%s=%s,%s=%s", labelKey, spec.ProfileName, models.ClientTypeLabel, models.ClientTypeSpiffe))
		if err != nil {
			return err
		}
		siblings, err := k8shelpers.ListServiceAccountsByLabel(ctx, deps.Client, namespace, selector)
		if err != nil {
			return err
		}
		stillActive := siblingsStillActive(siblings, saName)

		if spec.Cloud == "aws" {
			var profile myceliamv1.AwsAccessProfile
			found, err := k8shelpers.ReadAccessProfile(ctx, deps.Client, namespace, spec.ProfileName, &profile)
			if err != nil {
				return err
			}
			if !found {
				continue
			}
			for accountID, roles := range profile.Accounts {
				creds, err := operatoridentity.GetAWSCredentials(ctx, deps.Settings, accountID, deps.OIDC)
				if err != nil {
					return err
				}
				if spiffeID != "" {
					for _, role := range roles {
						if err := cloudaws.RemoveRoleTrust(ctx, accountID, role, jwtIssuer, "sub", spiffeID, creds); err != nil {
							return err
						}
					}
				}
				if !stillActive {
					if err := cloudaws.RemoveAudience(ctx, accountID, jwtIssuer, spec.Audience, creds); err != nil {
						return err
					}
				}
			}
		} else {
			var profile myceliamv1.GcpAccessProfile
			found, err := k8shelpers.ReadAccessProfile(ctx, deps.Client, namespace, spec.ProfileName, &profile)
			if err != nil {
				return err
			}
			if !found {
				continue
			}
			for projectID, emails := range profile.Projects {
				if spiffeID != "" {
					for _, email := range emails {
						if err := cloudgcp.RevokeImpersonation(ctx, email, projectID, spiffeID, deps.Settings, deps.OIDC); err != nil {
							return err
						}
					}
				}
				if !stillActive {
					if err := cloudgcp.DeleteIdp(ctx, projectID, namespace, deps.Settings, cloudgcp.KindSpiffe, deps.OIDC); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// cleanupSpiffe mirrors handlers.py's _cleanup_spiffe: full SA deletion —
// every profile currently referenced by this (departing) SA is a candidate
// for cleanup, under its last-known SPIFFE issuer/ID annotations.
func cleanupSpiffe(ctx context.Context, deps *Deps, namespace, saName string, labels, annotations map[string]string) error {
	jwtIssuer := annotations[models.SpiffeJWTIssuerAnnotation]
	spiffeID := annotations[models.SpiffeIDAnnotation]
	specs, err := cloudmodels.ParseCloudFederationSpecs(namespace, saName, labels, annotations, deps.Settings)
	if err != nil {
		// A departing SA with an already-invalid spec (e.g. role annotation
		// removed without removing the profile label first) shouldn't block
		// deletion — best-effort teardown of whatever we can still identify.
		return nil
	}
	return cleanupSpiffeSpecs(ctx, deps, namespace, saName, specs, jwtIssuer, spiffeID)
}

// removedSpecs mirrors handlers.py's _removed_specs: specs present under
// oldLabels/oldAnnotations but no longer present under labels/annotations (a
// profile label removed, or changed to a different profile).
func removedSpecs(namespace, saName string, oldLabels, oldAnnotations, labels, annotations map[string]string, deps *Deps) []cloudmodels.CloudFederationSpec {
	oldSpecs, err := cloudmodels.ParseCloudFederationSpecs(namespace, saName, oldLabels, oldAnnotations, deps.Settings)
	if err != nil {
		// The recorded "old" state was already invalid (shouldn't normally
		// happen — it must have passed validation to be recorded in the
		// first place) — nothing reliable to diff against.
		return nil
	}
	currentSpecs, err := cloudmodels.ParseCloudFederationSpecs(namespace, saName, labels, annotations, deps.Settings)
	if err != nil {
		// Current state doesn't parse (e.g. role annotation just removed) —
		// treat every old spec as removed rather than failing this diff.
		currentSpecs = nil
	}
	currentScopeNames := map[string]bool{}
	for _, s := range currentSpecs {
		currentScopeNames[s.ScopeName] = true
	}
	var removed []cloudmodels.CloudFederationSpec
	for _, s := range oldSpecs {
		if !currentScopeNames[s.ScopeName] {
			removed = append(removed, s)
		}
	}
	return removed
}

// refreshServiceAccountsForProfile fans out an AccessProfile CR create/update
// to reconcileCloud — the Keycloak-backed federation path — for every
// secret/signedjwt ServiceAccount in the namespace that references this
// profile. Deliberately excludes clienttype=spiffe SAs from the list, the
// same way cleanupCloud's own selector does: reconcileCloud looks up a
// Keycloak client for the SA's own name, which a spiffe SA never has (it's
// never registered as a Keycloak client at all — see reconcileSpiffe), so
// including one here would just retry a lookup that can never succeed,
// forever, every time this profile is touched. A spiffe SA's own cloud
// federation still gets refreshed on its own periodic cadence, via
// ServiceAccountReconciler's own reconcile loop — this fan-out was only ever
// meant to cover the Keycloak-backed clienttypes.
func refreshServiceAccountsForProfile(ctx context.Context, deps *Deps, namespace, labelKey, profileName string) error {
	selector, err := k8slabels.Parse(fmt.Sprintf("%s=%s,%s!=%s", labelKey, profileName, models.ClientTypeLabel, models.ClientTypeSpiffe))
	if err != nil {
		return err
	}
	sas, err := k8shelpers.ListServiceAccountsByLabel(ctx, deps.Client, namespace, selector)
	if err != nil {
		return err
	}
	for _, sa := range sas {
		if sa.Labels[models.AutoidpLabel] != "true" {
			continue
		}
		if err := reconcileCloud(ctx, deps, namespace, sa.Name, sa.Labels, sa.Annotations); err != nil {
			return err
		}
	}
	return nil
}

// owningSAName mirrors handlers.py's _owning_sa_name.
func owningSAName(secretName string, deps *Deps) (string, bool) {
	suffix := deps.Settings.CredentialsSecretSuffix
	if len(secretName) <= len(suffix) || secretName[len(secretName)-len(suffix):] != suffix {
		return "", false
	}
	return secretName[:len(secretName)-len(suffix)], true
}
