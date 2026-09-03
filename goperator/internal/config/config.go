// Package config loads operator configuration from MYCELIAM_* environment
// variables, mirroring pythonoperator/src/myceliam/config.py's pydantic-settings
// Settings class field-for-field (including defaults and validation).
package config

import (
	"fmt"
	"os"
	"strconv"
)

var knownOidcProviders = map[string]bool{
	"keycloak": true,
	"okta":     true,
	"auth0":    true,
	"none":     true,
}

// Settings is the operator's runtime configuration, loaded once at startup via Load().
type Settings struct {
	// Selects which oidc provider package memo.OIDC is built from — "keycloak"
	// (default), "okta" (scaffolded, not yet usable), "auth0" (not implemented at
	// all yet), or "none" for deployments that only ever use clienttype=spiffe
	// ServiceAccounts and don't want any Keycloak/Okta/Auth0 dependency at all.
	OidcProvider string

	KeycloakURL        string
	KeycloakAdminRealm string
	// KeycloakClientID identifies the operator's one Keycloak client — used
	// both for Admin REST API access and for the operator's own
	// cloud-federation token. Not a secret, just an identifier — kept as
	// plain config rather than a key inside myceliam-keycloak-secret /
	// myceliam-keycloak-keypair so the latter can stay a pure
	// kubernetes.io/tls secret (tls.crt/tls.key only), compatible with
	// cert-manager or any other standard TLS rotation tooling.
	KeycloakClientID  string
	KeycloakVerifySSL bool

	// Only relevant when NewProvider found myceliam-keycloak-keypair: how
	// long each freshly minted client assertion JWT is valid for (exp - iat).
	KeycloakAdminSignedjwtAssertionLifetimeSeconds int

	// SystemNamespace is the operator's own namespace — where NewProvider
	// looks for myceliam-keycloak-secret / myceliam-keycloak-keypair.
	SystemNamespace string

	// autoidp/clienttype/awsAccessProfile/gcpAccessProfile label *keys* are fixed
	// (myceliam.io/... constants in models/cloudmodels), not configurable here.
	// This one IS fully honored end-to-end: the Secret-watch predicate for
	// credentials-secret rotation reads MYCELIAM_CREDENTIALS_SECRET_SUFFIX directly
	// from the environment at startup, same pattern as ReconcileIntervalSeconds.
	CredentialsSecretSuffix string

	// Used only when a signedjwt client's <sa-name>-oidc-credentials secret doesn't
	// already exist and the operator has to generate the keypair itself.
	SignedjwtKeySize          int
	SignedjwtCertValidityDays int

	ReconcileIntervalSeconds float64

	// Optional client_credentials `scope` request for the operator's own
	// cloud-federation token (KeycloakProvider.GetOperatorToken) — Admin-API
	// tokens never request a scope.
	KeycloakOperatorScope string

	// Selects how the operator obtains its OWN bearer token to exchange for cloud
	// credentials (AWS AssumeRoleWithWebIdentity / GCP STS) — independent of
	// OidcProvider above. "keycloak" (default) uses the master-realm
	// client_credentials flow. "spiffe" fetches the operator's own JWT-SVID from
	// its local SPIRE agent instead.
	OperatorIdentitySource string

	// Only used when OperatorIdentitySource="spiffe": the audience to request when
	// fetching the operator's own JWT-SVID.
	OperatorSpiffeAudience string

	// AWS: IAM permissions are inherently account-scoped, so the operator assumes a
	// per-account role via AssumeRoleWithWebIdentity. Role *name* convention (same
	// in every account) — each target account still needs this role pre-provisioned.
	AwsOperatorRoleName string
	// RoleSessionName on that same AssumeRoleWithWebIdentity call.
	AwsOperatorSessionName string

	// ClusterID uniquely identifies this Kubernetes cluster among every other
	// cluster sharing the same Keycloak/AWS/GCP backends. Required (no
	// default): folded into every cluster-shared external resource's name —
	// the Keycloak realm (models.ParseClientSpec), the GCP WLI provider ID
	// (gcp.providerID) — since namespace names alone aren't guaranteed unique
	// across a fleet of clusters, and two clusters colliding on the same
	// namespace would otherwise silently clobber each other's realm/client/
	// provider. Also stamped as the myceliam.io/cluster-id attribute on every
	// Keycloak realm/client this operator manages, so a mismatch can be
	// detected and refused rather than silently adopted or overwritten.
	ClusterID string

	// GCP: a single service account can be granted IAM permissions across many
	// projects via cross-project policy bindings, so the operator only needs ONE
	// bootstrap Workload Identity Federation setup (in a single "hub" project).
	GcpOperatorSTSAudience         string
	GcpOperatorServiceAccountEmail string

	// The Workload Identity Pool ID that namespace/kind providers are registered
	// into — one such pool per GCP project listed across GcpAccessProfile CRs.
	GcpWorkloadIdentityPoolID string
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv("MYCELIAM_" + key); ok {
		return v
	}
	return def
}

func envBoolOr(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv("MYCELIAM_" + key)
	if !ok {
		return def, nil
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("invalid MYCELIAM_%s: %w", key, err)
	}
	return parsed, nil
}

func envIntOr(key string, def int) (int, error) {
	v, ok := os.LookupEnv("MYCELIAM_" + key)
	if !ok {
		return def, nil
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid MYCELIAM_%s: %w", key, err)
	}
	return parsed, nil
}

func envFloatOr(key string, def float64) (float64, error) {
	v, ok := os.LookupEnv("MYCELIAM_" + key)
	if !ok {
		return def, nil
	}
	parsed, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid MYCELIAM_%s: %w", key, err)
	}
	return parsed, nil
}

// Load reads Settings from MYCELIAM_* environment variables and validates them,
// mirroring config.py's get_settings()/Settings._validate_provider_config.
func Load() (*Settings, error) {
	s := &Settings{
		OidcProvider:                   envOr("OIDC_PROVIDER", "keycloak"),
		KeycloakURL:                    envOr("KEYCLOAK_URL", ""),
		KeycloakAdminRealm:             envOr("KEYCLOAK_ADMIN_REALM", "master"),
		KeycloakClientID:               envOr("KEYCLOAK_CLIENT_ID", "myceliam-operator"),
		CredentialsSecretSuffix:        envOr("CREDENTIALS_SECRET_SUFFIX", "-oidc-credentials"),
		SystemNamespace:                envOr("SYSTEM_NAMESPACE", "myceliam-system"),
		KeycloakOperatorScope:          envOr("KEYCLOAK_OPERATOR_SCOPE", ""),
		OperatorIdentitySource:         envOr("OPERATOR_IDENTITY_SOURCE", "keycloak"),
		OperatorSpiffeAudience:         envOr("OPERATOR_SPIFFE_AUDIENCE", ""),
		AwsOperatorRoleName:            envOr("AWS_OPERATOR_ROLE_NAME", "myceliam-operator"),
		AwsOperatorSessionName:         envOr("AWS_OPERATOR_SESSION_NAME", "myceliam-operator"),
		ClusterID:                      envOr("CLUSTER_ID", ""),
		GcpOperatorSTSAudience:         envOr("GCP_OPERATOR_STS_AUDIENCE", ""),
		GcpOperatorServiceAccountEmail: envOr("GCP_OPERATOR_SERVICE_ACCOUNT_EMAIL", ""),
		GcpWorkloadIdentityPoolID:      envOr("GCP_WORKLOAD_IDENTITY_POOL_ID", "myceliam-operator"),
	}

	var err error
	if s.KeycloakVerifySSL, err = envBoolOr("KEYCLOAK_VERIFY_SSL", true); err != nil {
		return nil, err
	}
	if s.KeycloakAdminSignedjwtAssertionLifetimeSeconds, err = envIntOr("KEYCLOAK_ADMIN_SIGNEDJWT_ASSERTION_LIFETIME_SECONDS", 60); err != nil {
		return nil, err
	}
	if s.SignedjwtKeySize, err = envIntOr("SIGNEDJWT_KEY_SIZE", 2048); err != nil {
		return nil, err
	}
	if s.SignedjwtCertValidityDays, err = envIntOr("SIGNEDJWT_CERT_VALIDITY_DAYS", 365); err != nil {
		return nil, err
	}
	if s.ReconcileIntervalSeconds, err = envFloatOr("RECONCILE_INTERVAL_SECONDS", 300); err != nil {
		return nil, err
	}

	if s.ClusterID == "" {
		return nil, fmt.Errorf(
			"MYCELIAM_CLUSTER_ID is required — it must uniquely identify this cluster " +
				"among every other cluster sharing the same Keycloak/AWS/GCP backends, " +
				"since realm and provider names are derived from it",
		)
	}

	if err := s.validateProviderConfig(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Settings) validateProviderConfig() error {
	if !knownOidcProviders[s.OidcProvider] {
		return fmt.Errorf(
			"unknown MYCELIAM_OIDC_PROVIDER: %q (expected one of [auth0 keycloak none okta])",
			s.OidcProvider,
		)
	}
	if s.OidcProvider == "keycloak" && s.KeycloakURL == "" {
		return fmt.Errorf(
			"MYCELIAM_KEYCLOAK_URL is required when MYCELIAM_OIDC_PROVIDER=keycloak " +
				"(the default) — set MYCELIAM_OIDC_PROVIDER=none instead for a deployment " +
				"that only ever uses clienttype=spiffe ServiceAccounts",
		)
	}
	return nil
}
