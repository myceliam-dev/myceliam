// Package config loads operator configuration from MYCELIAM_* environment
// variables, mirroring pythonoperator/src/myceliam/config.py's pydantic-settings
// Settings class field-for-field (including defaults and validation).
package config

import (
	"fmt"
	"os"
	"slices"
	"strconv"
)

// Settings is the operator's runtime configuration, loaded once at startup via Load().
type Settings struct {
	KeycloakURL        string
	KeycloakAdminRealm string

	// Auth0Domain is the pre-existing Auth0 tenant's domain (e.g.
	// "your-tenant.us.auth0.com") — its presence (alongside
	// Auth0OperatorClientID, required whenever this is set) is what makes
	// Auth0 one of ActiveProviders(). The tenant itself is
	// never created/managed by the operator. The operator's own Auth0
	// Management API credential lives in
	// myceliam-auth0-secret/myceliam-auth0-keypair in SystemNamespace (same
	// secret-or-keypair auto-detection as Keycloak's admin credential), read
	// directly by oidc/auth0.New.
	Auth0Domain string
	// Auth0OperatorClientID identifies the operator's own Auth0 Application
	// used to call the Management API — not a secret, just an identifier,
	// same reasoning as KeycloakClientID.
	Auth0OperatorClientID string
	// Auth0OperatorKeypairKid is only required when myceliam-auth0-keypair
	// is used: unlike Keycloak's single-certificate client-jwt mode (which
	// needs no kid at all), Auth0 assigns its own kid to an uploaded
	// credential — shown in the dashboard when the admin registers it — with
	// no way for the operator to derive or look it up itself beforehand
	// (doing so would require an already-authenticated Management API
	// session, exactly what's being bootstrapped).
	Auth0OperatorKeypairKid string
	// Auth0OperatorAudience is the Resource Server identifier the operator
	// requests when fetching its own AWS/GCP cloud-federation token
	// (Auth0Provider.GetOperatorToken) — the Auth0 analogue of
	// KeycloakOperatorScope, except mandatory rather than optional: unlike
	// Keycloak's scope->audience-mapper indirection, every Auth0 token
	// request must name its audience explicitly, so there's no "no audience
	// requested" fallback. Only required when OperatorProvider="auth0" —
	// checked lazily there, not here, mirroring Auth0OperatorKeypairKid's own
	// lazy check. The
	// operator provisions the matching Resource Server + its own Client
	// Grant itself on first use (see auth0.Provider.ensureOperatorAccessScope)
	// — this is just the identifier string, an admin never has to
	// pre-create anything in the Auth0 dashboard for it, unlike
	// KeycloakOperatorScope's admin-provisioned client scope.
	Auth0OperatorAudience string

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
	// Credentials/metadata secret naming is likewise fixed now (see
	// models.credentialsSecretNames) — no longer a single configurable
	// suffix, since it's a structured, provider/clienttype-varying name;
	// SecretReconciler identifies its own secrets via
	// models.ServiceAccountAnnotation instead of a name suffix.

	// Used only when a signedjwt client's credentials secret doesn't already
	// exist and the operator has to generate the keypair itself.
	SignedjwtKeySize          int
	SignedjwtCertValidityDays int

	ReconcileIntervalSeconds float64

	// Optional client_credentials `scope` request for the operator's own
	// cloud-federation token (KeycloakProvider.GetOperatorToken) — Admin-API
	// tokens never request a scope.
	KeycloakOperatorScope string

	// OperatorProvider selects which identity the operator itself uses to
	// obtain its OWN bearer token, exchanged for cloud credentials (AWS
	// AssumeRoleWithWebIdentity / GCP STS) — "keycloak"|"auth0"|"spiffe".
	// Fully decoupled from which providers are active for *workload*
	// provisioning (see ActiveProviders) — a real provider name here must
	// still be one of the active ones (its already-configured admin
	// credential is reused, the same way Keycloak's one client has always
	// served both the Admin API and the operator's own cloud-federation
	// token). Left empty by Load() when unset — validateProviderConfig
	// resolves the actual default (the sole active provider if there's
	// exactly one, "spiffe" if there are none, required explicitly if more
	// than one) rather than baking in a single hardcoded default the way the
	// single-provider world used to.
	OperatorProvider string

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
		KeycloakURL:                    envOr("KEYCLOAK_URL", ""),
		KeycloakAdminRealm:             envOr("KEYCLOAK_ADMIN_REALM", "master"),
		Auth0Domain:                    envOr("AUTH0_DOMAIN", ""),
		Auth0OperatorClientID:          envOr("AUTH0_OPERATOR_CLIENT_ID", ""),
		Auth0OperatorKeypairKid:        envOr("AUTH0_OPERATOR_KEYPAIR_KID", ""),
		Auth0OperatorAudience:          envOr("AUTH0_OPERATOR_AUDIENCE", ""),
		KeycloakClientID:               envOr("KEYCLOAK_CLIENT_ID", "myceliam-operator"),
		SystemNamespace:                envOr("SYSTEM_NAMESPACE", "myceliam-system"),
		KeycloakOperatorScope:          envOr("KEYCLOAK_OPERATOR_SCOPE", ""),
		OperatorProvider:               envOr("OPERATOR_PROVIDER", ""),
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

// ActiveProviders reports which of "keycloak"/"auth0" have their
// required config present — the operator provisions workload ServiceAccounts
// against every one of these simultaneously (see oidc.GetProviders), rather
// than a single globally-selected provider. A ServiceAccount picks which one
// it uses via the myceliam.io/oidc-provider label (models.OidcProviderLabel),
// defaulting automatically when exactly one is active. An empty result is
// valid — a deployment that only ever uses clienttype=spiffe ServiceAccounts
// and wants no Keycloak/Auth0 dependency at all (what MYCELIAM_OIDC_PROVIDER=none
// used to mean before this field existed).
func (s *Settings) ActiveProviders() []string {
	var active []string
	if s.KeycloakURL != "" {
		active = append(active, "keycloak")
	}
	if s.Auth0Domain != "" && s.Auth0OperatorClientID != "" {
		active = append(active, "auth0")
	}
	return active
}

func (s *Settings) validateProviderConfig() error {
	// Checked unconditionally (not just when Auth0 would otherwise be
	// "active") so a domain set without a client ID surfaces as a clear
	// config error instead of Auth0 silently never activating.
	if s.Auth0Domain != "" && s.Auth0OperatorClientID == "" {
		return fmt.Errorf(
			"MYCELIAM_AUTH0_OPERATOR_CLIENT_ID is required when MYCELIAM_AUTH0_DOMAIN is set",
		)
	}

	active := s.ActiveProviders()
	switch {
	case s.OperatorProvider != "":
		if s.OperatorProvider != "spiffe" && !slices.Contains(active, s.OperatorProvider) {
			return fmt.Errorf(
				"MYCELIAM_OPERATOR_PROVIDER=%q must be \"spiffe\" or one of the active OIDC "+
					"providers (currently: %v) — a provider needs its own config present "+
					"(MYCELIAM_KEYCLOAK_URL / "+
					"MYCELIAM_AUTH0_DOMAIN+MYCELIAM_AUTH0_OPERATOR_CLIENT_ID) before the "+
					"operator can use it for its own cloud-federation identity",
				s.OperatorProvider, active,
			)
		}
	case len(active) == 1:
		s.OperatorProvider = active[0]
	case len(active) == 0:
		s.OperatorProvider = "spiffe"
	default:
		return fmt.Errorf(
			"MYCELIAM_OPERATOR_PROVIDER is required when more than one OIDC provider is "+
				"configured (currently active: %v) — set it to one of them, or to \"spiffe\", "+
				"to select which identity the operator itself uses for its own AWS/GCP "+
				"cloud-federation credentials, independent of which providers workload "+
				"ServiceAccounts use",
			active,
		)
	}
	return nil
}
