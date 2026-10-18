// Package models ports pythonoperator/src/myceliam/models.py: the
// ServiceAccount label/annotation constants and the ClientSpec derivation
// shared by every clienttype=secret/signedjwt reconcile path.
package models

import (
	"fmt"

	"myceliam/internal/config"
	"myceliam/internal/operr"
)

const (
	AutoidpLabel    = "myceliam.io/autoidp"
	ClientTypeLabel = "myceliam.io/client-type"

	// OidcProviderLabel selects which of config.Settings.ActiveProviders()
	// a secret/signedjwt ServiceAccount is provisioned against — e.g.
	// "keycloak" or "auth0". Optional when exactly one provider is
	// active (the caller then defaults to it automatically — see
	// controller.resolveProviderName); required, and validated against the
	// actually-active set, whenever more than one provider is configured on
	// this operator. Irrelevant to clienttype=spiffe ServiceAccounts, which
	// never touch any of these providers at all.
	OidcProviderLabel = "myceliam.io/oidc-provider"

	// SpiffeJWTIssuerAnnotation is required on a ServiceAccount when
	// ClientTypeLabel is "spiffe": the SPIRE trust domain's JWT-SVID issuer URL
	// (e.g. "https://spire-oidc.example.com"), used as the AWS/GCP IdP's issuer
	// and to fetch JWKS for JWT validation — there's no Keycloak realm to derive
	// it from for this client type, so it must be supplied explicitly.
	SpiffeJWTIssuerAnnotation = "myceliam.io/spiffe-jwt-issuer"

	// SpiffeIDAnnotation is required on a clienttype=spiffe ServiceAccount
	// only when it also requests role-scoped cloud federation (an
	// AwsProfileLabel/GcpProfileLabel is present): the exact SPIFFE ID SPIRE
	// issues this workload (e.g. "spiffe://example.org/ns/demo/sa/app"). AWS
	// IAM trust-policy conditions and GCP WLI impersonation grants both need
	// a concrete per-entity value to scope to — for Keycloak-issued tokens
	// that's the SA name (the azp claim), but SPIFFE JWT-SVIDs carry no azp
	// claim at all, only sub (the SPIFFE ID itself). Since SPIRE registration
	// entries are fully admin-configured, myceliam has no reliable way to
	// derive this string on its own — it must be supplied explicitly, same
	// reasoning as SpiffeJWTIssuerAnnotation above.
	SpiffeIDAnnotation = "myceliam.io/spiffe-id"

	// ServiceAccountAnnotation is written by the operator (not admin-supplied,
	// unlike the two above) onto every credentials/metadata Secret it creates
	// for a secret/signedjwt ServiceAccount, carrying that SA's exact name.
	// SecretReconciler reads this directly to recover the owning SA, rather
	// than parsing it back out of the Secret's own name — necessary now that
	// naming is a compound, provider/clienttype-varying string
	// (credentialsSecretNames) rather than one fixed suffix, and more robust
	// generally regardless: an annotation has no length limit, unlike a label
	// value's 63-character cap, which is already too short for the legal
	// 253-character range of a Kubernetes ServiceAccount name.
	ServiceAccountAnnotation = "myceliam.io/service-account"
)

// ClientType mirrors models.py's ClientType(str, Enum).
type ClientType string

const (
	ClientTypeSecret    ClientType = "secret"
	ClientTypeSignedJWT ClientType = "signedjwt"
	ClientTypeSpiffe    ClientType = "spiffe"
)

// ClientSpec is the desired Keycloak client configuration derived from a
// ServiceAccount's namespace/name/labels.
type ClientSpec struct {
	Realm      string
	ClientName string
	ClientType ClientType
	// CredentialsSecretName holds the actual credential material: Opaque
	// (client_id/client_secret/issuer) for ClientTypeSecret, TLS
	// (tls.crt/tls.key only, kept pure for cert-manager compatibility) for
	// ClientTypeSignedJWT — see credentialsSecretNames.
	CredentialsSecretName string
	// MetadataSecretName is only meaningful for ClientTypeSignedJWT: an
	// Opaque companion secret holding client_id + kid, since neither belongs
	// in the TLS secret above. Unused (but still populated) for
	// ClientTypeSecret, where CredentialsSecretName already carries
	// client_id directly.
	MetadataSecretName string
}

// RealmForNamespace derives the Keycloak realm name for namespace: the sole
// place this cluster-prefixing convention lives, so every caller that needs
// "the realm for this namespace" (ParseClientSpec here, but also
// reconcileCloud/cleanupCloud's own IssuerURL lookups in controller/reconcile.go,
// which don't go through a ClientSpec at all) computes the exact same string.
// Cluster-prefixed so two clusters sharing this Keycloak instance never
// collide on the same realm just because they happen to have a namespace
// with the same name — see config.Settings.ClusterID's own doc comment.
func RealmForNamespace(namespace string, settings *config.Settings) string {
	return fmt.Sprintf("%s-%s", settings.ClusterID, namespace)
}

// credentialsSecretNames derives the two possible secret names for a
// secret/signedjwt ServiceAccount: "<sa>-<tag>-<provider>-credentials" (the
// actual credential material) and "<sa>-<tag>-<provider>-metadata"
// (client_id + kid, only ever written for ClientTypeSignedJWT — see
// ClientSpec.MetadataSecretName's doc comment). Folding both clientType and
// provider into the name means two different providers' credentials for the
// same SA — or a secret- and a signedjwt-typed client on it — never collide
// on one secret, which secret/signedjwt-per-provider coexistence on a single
// SA will eventually need.
//
// Truncation for Kubernetes' 253-character object-name limit is deliberately
// not handled here — an oversized name surfaces as a normal Kubernetes
// validation error on create/update (retried like any other *operr.Temporary),
// not a silent corruption — revisit if this proves to matter in practice.
func credentialsSecretNames(saName string, clientType ClientType, provider string) (credentials, metadata string) {
	tag := "secret"
	if clientType == ClientTypeSignedJWT {
		tag = "jwt"
	}
	return fmt.Sprintf("%s-%s-%s-credentials", saName, tag, provider),
		fmt.Sprintf("%s-%s-%s-metadata", saName, tag, provider)
}

// ParseClientSpec derives the desired Keycloak client configuration from a
// ServiceAccount's namespace/name/labels. provider is the already-resolved
// OIDC provider name this SA is provisioned against (see
// controller.resolveProviderName) — ParseClientSpec itself no longer reads
// OidcProviderLabel or picks a default; it just uses whatever the caller
// resolved.
//
// Returns an *operr.Permanent for malformed input a retry cannot fix.
func ParseClientSpec(namespace, name string, labels map[string]string, provider string, settings *config.Settings) (*ClientSpec, error) {
	rawType := labels[ClientTypeLabel]
	if rawType != string(ClientTypeSecret) && rawType != string(ClientTypeSignedJWT) {
		return nil, operr.Permanentf(
			"ServiceAccount '%s/%s' has label '%s=true' but '%s' is missing or "+
				"invalid (got %q); expected '%s' or '%s'.",
			namespace, name, AutoidpLabel, ClientTypeLabel, rawType,
			ClientTypeSecret, ClientTypeSignedJWT,
		)
	}
	clientType := ClientType(rawType)
	credentialsSecretName, metadataSecretName := credentialsSecretNames(name, clientType, provider)

	return &ClientSpec{
		Realm:                 RealmForNamespace(namespace, settings),
		ClientName:            name,
		ClientType:            clientType,
		CredentialsSecretName: credentialsSecretName,
		MetadataSecretName:    metadataSecretName,
	}, nil
}
