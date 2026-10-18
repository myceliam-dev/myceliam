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

// resolveProviderName picks which of deps.OIDCProviders a given
// ServiceAccount uses: the myceliam.io/oidc-provider label if set (validated
// against the actually-active set), else the sole active provider when
// there's exactly one (so a single-provider deployment needs no label at
// all), else an error demanding the label when more than one provider is
// active, else an error when none are configured at all.
func resolveProviderName(deps *Deps, namespace, name string, labels map[string]string) (string, error) {
	if v, ok := labels[models.OidcProviderLabel]; ok && v != "" {
		if _, exists := deps.OIDCProviders[v]; !exists {
			return "", operr.Permanentf(
				"ServiceAccount '%s/%s' requests '%s=%s', but no OIDC provider config for "+
					"%q is active on this operator (active: %v)",
				namespace, name, models.OidcProviderLabel, v, v, activeProviderNames(deps),
			)
		}
		return v, nil
	}
	switch len(deps.OIDCProviders) {
	case 1:
		for k := range deps.OIDCProviders {
			return k, nil
		}
	case 0:
		return "", operr.Permanentf(
			"ServiceAccount '%s/%s' needs a Keycloak/Auth0-backed client "+
				"(clienttype=secret/signedjwt), but no OIDC provider is configured on this "+
				"operator (set MYCELIAM_KEYCLOAK_URL / "+
				"MYCELIAM_AUTH0_DOMAIN+MYCELIAM_AUTH0_OPERATOR_CLIENT_ID to use this client "+
				"type, or use clienttype=spiffe instead if this ServiceAccount doesn't need one).",
			namespace, name,
		)
	}
	return "", operr.Permanentf(
		"ServiceAccount '%s/%s' must set label '%s' — more than one OIDC provider is "+
			"configured on this operator (active: %v) and none can be inferred as a default.",
		namespace, name, models.OidcProviderLabel, activeProviderNames(deps),
	)
}

// operatorClientIdentifiers returns the client_id/audience strings that
// identify the operator's own bootstrap identity for providerName — only
// non-empty when the operator actually uses that provider for its own
// AWS/GCP credentials (deps.Settings.OperatorProvider == providerName).
// Passed to cloudaws.DeleteIdp so it refuses to delete an IAM OIDC provider
// the operator itself still depends on — see DeleteIdp's own doc comment
// for the live incident this guards against.
func operatorClientIdentifiers(deps *Deps, providerName string) []string {
	if deps.Settings.OperatorProvider != providerName {
		return nil
	}
	switch providerName {
	case "keycloak":
		return []string{deps.Settings.KeycloakClientID}
	case "auth0":
		return []string{deps.Settings.Auth0OperatorClientID, deps.Settings.Auth0OperatorAudience}
	default:
		return nil
	}
}

func activeProviderNames(deps *Deps) []string {
	names := make([]string, 0, len(deps.OIDCProviders))
	for k := range deps.OIDCProviders {
		names = append(names, k)
	}
	return names
}

// requireOIDC resolves both the provider name and the *oidc.Provider
// instance a ServiceAccount uses — see resolveProviderName for the selection
// rules.
func requireOIDC(deps *Deps, namespace, name string, labels map[string]string) (string, oidc.Provider, error) {
	providerName, err := resolveProviderName(deps, namespace, name, labels)
	if err != nil {
		return "", nil, err
	}
	return providerName, deps.OIDCProviders[providerName], nil
}

// reconcileClient mirrors handlers.py's _reconcile: ensures the realm/client
// (and, for signedjwt, the keypair Secret + JWKS) for a secret/signedjwt
// ServiceAccount. Gated on the AutoidpAllowlist — see requireNamespaceAllowed.
func reconcileClient(ctx context.Context, deps *Deps, namespace, name string, labels map[string]string, owner metav1.OwnerReference) error {
	if err := requireNamespaceAllowed(ctx, deps, namespace, name); err != nil {
		return err
	}

	providerName, oidcProvider, err := requireOIDC(deps, namespace, name, labels)
	if err != nil {
		return err
	}

	spec, err := models.ParseClientSpec(namespace, name, labels, providerName, deps.Settings)
	if err != nil {
		return err
	}
	if err := oidcProvider.EnsureTenant(ctx, spec.Realm); err != nil {
		return err
	}

	ownerAnnotations := map[string]string{models.ServiceAccountAnnotation: name}

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
		}, ownerAnnotations, owner)
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
		if err := k8shelpers.CreateTLSSecretIfAbsent(ctx, deps.Client, namespace, spec.CredentialsSecretName, certPEM, keyPEM, ownerAnnotations, owner); err != nil {
			return err
		}
	}
	jwk, err := jwks.PemCertToJWK(certPEM)
	if err != nil {
		return err
	}
	jwksString, err := jwks.PemCertToJWKSString(certPEM)
	if err != nil {
		return err
	}
	clientID, actualKid, err := oidcProvider.EnsureSignedjwtClient(ctx, spec, certPEM, jwksString, jwk.Kid)
	if err != nil {
		return err
	}
	return k8shelpers.WriteCredentialsSecret(ctx, deps.Client, namespace, spec.MetadataSecretName, map[string]string{
		"client_id": clientID,
		"kid":       actualKid,
	}, ownerAnnotations, owner)
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

	providerName, oidcProvider, err := requireOIDC(deps, namespace, saName, labels)
	if err != nil {
		return err
	}

	specs, err := cloudmodels.ParseCloudFederationSpecs(namespace, saName, labels, annotations, providerName, deps.Settings)
	if err != nil {
		return err
	}
	if len(specs) == 0 {
		return nil
	}

	issuerURL, err := oidcProvider.IssuerURL(models.RealmForNamespace(namespace, deps.Settings))
	if err != nil {
		return err
	}

	for _, spec := range specs {
		azpValue, err := oidcProvider.EnsureAccessScope(ctx, models.RealmForNamespace(namespace, deps.Settings), saName, spec.ScopeName, spec.Audience)
		if err != nil {
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
			// azpValue may already equal saName (Keycloak) — dedupe so
			// ClientIDList/EnsureIdp's existing-entries check doesn't try to
			// add the same client ID twice.
			audiences := []string{spec.Audience, saName}
			if azpValue != "" && azpValue != saName {
				audiences = append(audiences, azpValue)
			}
			for accountID, roles := range profile.Accounts {
				creds, err := operatoridentity.GetAWSCredentials(ctx, deps.Settings, accountID, deps.OperatorOIDC)
				if err != nil {
					return err
				}
				if err := cloudaws.EnsureIdp(ctx, accountID, issuerURL, audiences, creds); err != nil {
					return err
				}
				for _, role := range roles {
					if err := cloudaws.EnsureRoleTrust(ctx, accountID, role, issuerURL, spec.Audience, spec.SubjectClaim, saName, azpValue, spec.SharedAudience, spec.SubjectClaimViaSessionTag, creds); err != nil {
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
				if err := cloudgcp.EnsureIdp(ctx, projectID, namespace, issuerURL, spec.Audience, deps.Settings, cloudgcp.KindOIDC, providerName, deps.OperatorOIDC); err != nil {
					return err
				}
				for _, email := range emails {
					if err := cloudgcp.GrantImpersonation(ctx, email, projectID, saName, deps.Settings, deps.OperatorOIDC); err != nil {
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
func cleanupCloud(ctx context.Context, deps *Deps, namespace, saName string, labels map[string]string, specs []cloudmodels.CloudFederationSpec) error {
	if len(specs) == 0 {
		return nil
	}
	providerName, oidcProvider, err := requireOIDC(deps, namespace, saName, labels)
	if err != nil {
		return err
	}

	for _, spec := range specs {
		if err := oidcProvider.DeleteAccessScope(ctx, models.RealmForNamespace(namespace, deps.Settings), saName, spec.ScopeName); err != nil {
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
				creds, err := operatoridentity.GetAWSCredentials(ctx, deps.Settings, accountID, deps.OperatorOIDC)
				if err != nil {
					return err
				}
				for _, role := range roles {
					if err := cloudaws.RemoveRoleTrust(ctx, accountID, role, issuerURL, spec.SubjectClaim, saName, creds); err != nil {
						return err
					}
				}
				if stillActive || spec.IssuerShared {
					err = cloudaws.RemoveAudience(ctx, accountID, issuerURL, saName, creds)
				} else {
					err = cloudaws.DeleteIdp(ctx, accountID, issuerURL, operatorClientIdentifiers(deps, providerName), creds)
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
					if err := cloudgcp.RevokeImpersonation(ctx, email, projectID, saName, deps.Settings, deps.OperatorOIDC); err != nil {
						return err
					}
				}
				if !stillActive {
					if err := cloudgcp.DeleteIdp(ctx, projectID, namespace, deps.Settings, cloudgcp.KindOIDC, providerName, deps.OperatorOIDC); err != nil {
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

	specs, err := cloudmodels.ParseCloudFederationSpecs(namespace, saName, labels, annotations, "", deps.Settings)
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
				creds, err := operatoridentity.GetAWSCredentials(ctx, deps.Settings, accountID, deps.OperatorOIDC)
				if err != nil {
					return err
				}
				if err := cloudaws.EnsureIdp(ctx, accountID, jwtIssuer, []string{spec.Audience}, creds); err != nil {
					return err
				}
				for _, role := range roles {
					if err := cloudaws.EnsureRoleTrust(ctx, accountID, role, jwtIssuer, spec.Audience, "sub", spiffeID, "", spec.SharedAudience, false, creds); err != nil {
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
				if err := cloudgcp.EnsureIdp(ctx, projectID, namespace, jwtIssuer, spec.Audience, deps.Settings, cloudgcp.KindSpiffe, "", deps.OperatorOIDC); err != nil {
					return err
				}
				for _, email := range emails {
					if err := cloudgcp.GrantImpersonation(ctx, email, projectID, spiffeID, deps.Settings, deps.OperatorOIDC); err != nil {
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
				creds, err := operatoridentity.GetAWSCredentials(ctx, deps.Settings, accountID, deps.OperatorOIDC)
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
						if err := cloudgcp.RevokeImpersonation(ctx, email, projectID, spiffeID, deps.Settings, deps.OperatorOIDC); err != nil {
							return err
						}
					}
				}
				if !stillActive {
					if err := cloudgcp.DeleteIdp(ctx, projectID, namespace, deps.Settings, cloudgcp.KindSpiffe, "", deps.OperatorOIDC); err != nil {
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
	specs, err := cloudmodels.ParseCloudFederationSpecs(namespace, saName, labels, annotations, "", deps.Settings)
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
// profile label removed, or changed to a different profile). Resolves the
// provider name itself from the *current* labels (empty for spiffe SAs,
// which have no OIDC workload provider at all) and reuses it for both the
// old and current parse — an SA changing which provider it uses mid-lifecycle
// isn't a case this diff needs to handle precisely, since that's a much
// bigger change (different backend entirely) than a profile label flip.
func removedSpecs(namespace, saName string, oldLabels, oldAnnotations, labels, annotations map[string]string, deps *Deps) []cloudmodels.CloudFederationSpec {
	var providerName string
	if labels[models.ClientTypeLabel] != string(models.ClientTypeSpiffe) {
		providerName, _ = resolveProviderName(deps, namespace, saName, labels)
	}

	oldSpecs, err := cloudmodels.ParseCloudFederationSpecs(namespace, saName, oldLabels, oldAnnotations, providerName, deps.Settings)
	if err != nil {
		// The recorded "old" state was already invalid (shouldn't normally
		// happen — it must have passed validation to be recorded in the
		// first place) — nothing reliable to diff against.
		return nil
	}
	currentSpecs, err := cloudmodels.ParseCloudFederationSpecs(namespace, saName, labels, annotations, providerName, deps.Settings)
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
