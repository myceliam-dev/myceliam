// Package operatoridentity ports pythonoperator/src/myceliam/operator_identity.py:
// the operator's own credential-exchange path, distinct from the
// per-ServiceAccount client provisioning oidc.Provider handles. Obtains a
// token for the operator's own pre-provisioned identity (Keycloak- or
// SPIFFE-issued, per Settings.OperatorIdentitySource) and exchanges it for
// short-lived AWS/GCP credentials via AssumeRoleWithWebIdentity / GCP STS.
package operatoridentity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	cloudaws "myceliam/internal/cloudproviders/aws"
	"myceliam/internal/config"
	"myceliam/internal/httpx"
	"myceliam/internal/oidc"
	"myceliam/internal/operr"
)

const spiffeEndpointSocketEnv = "SPIFFE_ENDPOINT_SOCKET"

// gcpSTSTokenURL/gcpIAMCredentialsURLFmt are package-level vars (rather than
// consts) purely so tests can point them at an httptest.Server instead of
// Google's real endpoints.
var (
	gcpSTSTokenURL          = "https://sts.googleapis.com/v1/token"
	gcpIAMCredentialsURLFmt = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
)

// fetchSpiffeJWTSVID is a package-level seam over the go-spiffe Workload API
// call itself, isolated so getOperatorSpiffeToken's own validation logic
// (audience/socket env var required) can be unit-tested without a running
// SPIRE agent.
var fetchSpiffeJWTSVID = func(ctx context.Context, audience, addr string) (string, error) {
	svid, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience}, workloadapi.WithAddr(addr))
	if err != nil {
		return "", err
	}
	return svid.Marshal(), nil
}

// getOperatorSpiffeToken fetches the operator's own JWT-SVID from its local
// SPIRE agent's Workload API — used instead of a Keycloak master-realm token
// when OperatorIdentitySource is "spiffe". The operator's own pod needs the
// same spiffe-csi-driver volume mount (and SPIFFE_ENDPOINT_SOCKET env var)
// any clienttype=spiffe ServiceAccount gets.
//
// Unlike pythonoperator's equivalent — which shells out to the spire-agent
// CLI and parses its plain-text output, because that CLI has no machine-
// readable --output flag — this talks to the Workload API directly over gRPC
// via go-spiffe/v2, so there's no external binary to bundle in the operator
// image and no text-parsing step at all.
func getOperatorSpiffeToken(ctx context.Context, settings *config.Settings) (string, error) {
	if settings.OperatorSpiffeAudience == "" {
		return "", operr.Permanentf(
			"MYCELIAM_OPERATOR_SPIFFE_AUDIENCE must be set when " +
				"MYCELIAM_OPERATOR_IDENTITY_SOURCE=spiffe — it must match whatever audience " +
				"the admin configured on the bootstrap AWS IdP's ClientIDList / GCP WLI " +
				"provider's allowedAudiences.",
		)
	}

	endpoint, ok := os.LookupEnv(spiffeEndpointSocketEnv)
	if !ok || endpoint == "" {
		return "", operr.Permanentf(
			"SPIFFE_ENDPOINT_SOCKET must be set (as a unix:///path URI) when " +
				"MYCELIAM_OPERATOR_IDENTITY_SOURCE=spiffe, so the operator can reach its " +
				"local SPIRE agent's Workload API.",
		)
	}

	token, err := fetchSpiffeJWTSVID(ctx, settings.OperatorSpiffeAudience, endpoint)
	if err != nil {
		return "", operr.Temporaryf(30*time.Second, "Error fetching operator JWT-SVID from SPIRE Workload API: %v", err)
	}
	return token, nil
}

// getOperatorToken obtains an access token for the operator's own
// pre-provisioned identity, to be exchanged for cloud credentials via
// AWS/GCP STS. Dispatches on Settings.OperatorIdentitySource: "spiffe"
// fetches the operator's own JWT-SVID directly; anything else (default
// "keycloak") delegates to whichever oidc.Provider is configured (the same
// long-lived instance built once at startup and threaded through Deps.OIDC —
// reusing it, rather than building a fresh one per call, is what lets
// KeycloakProvider's token caching actually do anything) rather than
// hardcoding Keycloak.
func getOperatorToken(ctx context.Context, settings *config.Settings, provider oidc.Provider) (string, error) {
	if settings.OperatorIdentitySource == "spiffe" {
		return getOperatorSpiffeToken(ctx, settings)
	}
	if provider == nil {
		// MYCELIAM_OIDC_PROVIDER=none with OperatorIdentitySource left at its
		// "keycloak" default: a deployment that opted out of the
		// per-ServiceAccount OIDC provider but never redirected its own
		// operator identity to spiffe either. pythonoperator has no
		// equivalent guard here (its get_provider(...).get_operator_token()
		// would raise a bare AttributeError on None) — this surfaces the
		// same misconfiguration as a clear PermanentError instead of a panic.
		return "", operr.Permanentf(
			"MYCELIAM_OPERATOR_IDENTITY_SOURCE=keycloak requires MYCELIAM_OIDC_PROVIDER to be " +
				"set to a real provider (not 'none') — set MYCELIAM_OPERATOR_IDENTITY_SOURCE=spiffe " +
				"instead if this deployment has no Keycloak/Okta/Auth0 provider configured.",
		)
	}
	return provider.GetOperatorToken(ctx)
}

// stsAPI is the subset of *sts.Client this package calls, matching its real
// method signature exactly so *sts.Client satisfies it with no glue code.
type stsAPI interface {
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

// newSTSClient is a package-level factory var so tests can inject a fake.
var newSTSClient = func() stsAPI {
	// AssumeRoleWithWebIdentity is explicitly designed to be callable without
	// any prior AWS credentials — that's the whole point of federation.
	// AnonymousCredentials tells the SDK's signing middleware not to attempt
	// SigV4 signing at all (the Go equivalent of botocore's
	// Config(signature_version=UNSIGNED)) — sts.NewFromConfig without it
	// would still eagerly resolve the default credential chain, which is
	// meaningless (and can fail outright) in a pod with no ~/.aws config.
	return sts.NewFromConfig(awssdk.Config{
		Region:      "us-east-1",
		Credentials: awssdk.AnonymousCredentials{},
	})
}

// GetAWSCredentials exchanges the operator's own token (Keycloak- or
// SPIFFE-issued, per Settings.OperatorIdentitySource) for short-lived AWS
// credentials via AssumeRoleWithWebIdentity, targeting the pre-provisioned
// per-account operator role.
func GetAWSCredentials(ctx context.Context, settings *config.Settings, accountID string, provider oidc.Provider) (cloudaws.Credentials, error) {
	token, err := getOperatorToken(ctx, settings, provider)
	if err != nil {
		return cloudaws.Credentials{}, err
	}

	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, settings.AwsOperatorRoleName)
	client := newSTSClient()
	out, err := client.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          awssdk.String(roleArn),
		RoleSessionName:  awssdk.String(settings.AwsOperatorSessionName),
		WebIdentityToken: awssdk.String(token),
	})
	if err != nil {
		return cloudaws.Credentials{}, operr.Temporaryf(30*time.Second, "Error assuming role '%s' via web identity: %v", roleArn, err)
	}

	creds := out.Credentials
	return cloudaws.Credentials{
		AccessKeyID:     awssdk.ToString(creds.AccessKeyId),
		SecretAccessKey: awssdk.ToString(creds.SecretAccessKey),
		SessionToken:    awssdk.ToString(creds.SessionToken),
	}, nil
}

func postJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, body any) (int, []byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(b)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, respBody, nil
}

// GetGCPAccessToken exchanges the operator's own token (Keycloak- or
// SPIFFE-issued, per Settings.OperatorIdentitySource) for a GCP access token:
// first via GCP STS token exchange (against the pre-provisioned bootstrap
// Workload Identity Pool), then impersonating the pre-provisioned hub service
// account for the final access token. That service account must already have
// IAM permissions in every target project.
func GetGCPAccessToken(ctx context.Context, settings *config.Settings, provider oidc.Provider) (string, error) {
	if settings.GcpOperatorSTSAudience == "" || settings.GcpOperatorServiceAccountEmail == "" {
		return "", operr.Permanentf(
			"MYCELIAM_GCP_OPERATOR_STS_AUDIENCE / MYCELIAM_GCP_OPERATOR_SERVICE_ACCOUNT_EMAIL " +
				"must be set for GCP IdP federation (the operator's own pre-provisioned " +
				"Workload Identity Federation bootstrap).",
		)
	}

	operatorToken, err := getOperatorToken(ctx, settings, provider)
	if err != nil {
		return "", err
	}

	client := httpx.NewClient(true) // talking to Google's own endpoints, not Keycloak — always verified
	status, body, err := postJSON(ctx, client, gcpSTSTokenURL, nil, map[string]any{
		"audience":           settings.GcpOperatorSTSAudience,
		"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
		"subjectToken":       operatorToken,
		"scope":              "https://www.googleapis.com/auth/cloud-platform",
	})
	if err != nil {
		return "", operr.Temporaryf(30*time.Second, "Error obtaining GCP credentials via STS/impersonation: %v", err)
	}
	if status >= 300 {
		return "", gcpExchangeError(status, body)
	}
	var exchangeResult struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &exchangeResult); err != nil {
		return "", operr.Temporaryf(30*time.Second, "Error decoding GCP STS exchange response: %v", err)
	}

	impersonateURL := fmt.Sprintf(gcpIAMCredentialsURLFmt, settings.GcpOperatorServiceAccountEmail)
	status, body, err = postJSON(ctx, client, impersonateURL,
		map[string]string{"Authorization": "Bearer " + exchangeResult.AccessToken},
		map[string]any{"scope": []string{"https://www.googleapis.com/auth/cloud-platform"}},
	)
	if err != nil {
		return "", operr.Temporaryf(30*time.Second, "Error obtaining GCP credentials via STS/impersonation: %v", err)
	}
	if status >= 300 {
		return "", gcpExchangeError(status, body)
	}
	var impersonateResult struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(body, &impersonateResult); err != nil {
		return "", operr.Temporaryf(30*time.Second, "Error decoding GCP impersonation response: %v", err)
	}
	return impersonateResult.AccessToken, nil
}

func gcpExchangeError(status int, body []byte) error {
	// str(exc) alone (e.g. "400 Client Error: Bad Request for url: ...") omits
	// the actual response body, which for a 4xx from either endpoint here
	// carries Google's own explanation (invalid audience format, unauthorized
	// subject, etc.) — surface it explicitly or failures here are
	// undiagnosable from the operator's own logs.
	return operr.Temporaryf(
		30*time.Second,
		"Error obtaining GCP credentials via STS/impersonation: %d — response body: %s",
		status, strings.TrimSpace(string(body)),
	)
}
