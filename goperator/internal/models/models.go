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
	Realm                 string
	ClientName            string
	ClientType            ClientType
	CredentialsSecretName string
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

// ParseClientSpec derives the desired Keycloak client configuration from a
// ServiceAccount's namespace/name/labels.
//
// Returns an *operr.Permanent for malformed input a retry cannot fix.
func ParseClientSpec(namespace, name string, labels map[string]string, settings *config.Settings) (*ClientSpec, error) {
	rawType := labels[ClientTypeLabel]
	if rawType != string(ClientTypeSecret) && rawType != string(ClientTypeSignedJWT) {
		return nil, operr.Permanentf(
			"ServiceAccount '%s/%s' has label '%s=true' but '%s' is missing or "+
				"invalid (got %q); expected '%s' or '%s'.",
			namespace, name, AutoidpLabel, ClientTypeLabel, rawType,
			ClientTypeSecret, ClientTypeSignedJWT,
		)
	}

	return &ClientSpec{
		Realm:                 RealmForNamespace(namespace, settings),
		ClientName:            name,
		ClientType:            ClientType(rawType),
		CredentialsSecretName: fmt.Sprintf("%s%s", name, settings.CredentialsSecretSuffix),
	}, nil
}
