package operatoridentity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"myceliam/internal/config"
	"myceliam/internal/models"
	"myceliam/internal/oidc"
	"myceliam/internal/operr"
)

func testSettings(t *testing.T, overrides map[string]string) *config.Settings {
	t.Helper()
	t.Setenv("MYCELIAM_KEYCLOAK_URL", "https://kc.example.com")
	t.Setenv("MYCELIAM_CLUSTER_ID", "test-cluster")
	for k, v := range overrides {
		t.Setenv("MYCELIAM_"+k, v)
	}
	s, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return s
}

var _ oidc.Provider = (*fakeProvider)(nil)

// fakeProvider is a minimal oidc.Provider test double for exercising
// getOperatorToken's delegation to the configured provider.
type fakeProvider struct {
	operatorToken string
	err           error
	calls         int
}

func (f *fakeProvider) EnsureTenant(context.Context, string) error { return nil }
func (f *fakeProvider) DeleteTenant(context.Context, string) error { return nil }
func (f *fakeProvider) EnsureSecretClient(context.Context, *models.ClientSpec) (string, string, error) {
	return "", "", nil
}
func (f *fakeProvider) EnsureSignedjwtClient(context.Context, *models.ClientSpec, string) (string, error) {
	return "", nil
}
func (f *fakeProvider) DeleteClient(context.Context, string, string) error { return nil }
func (f *fakeProvider) IssuerURL(string) (string, error)                   { return "", nil }
func (f *fakeProvider) EnsureAccessScope(context.Context, string, string, string, string) error {
	return nil
}
func (f *fakeProvider) DeleteAccessScope(context.Context, string, string) error { return nil }
func (f *fakeProvider) GetOperatorToken(context.Context) (string, error) {
	f.calls++
	return f.operatorToken, f.err
}

func TestGetOperatorTokenDelegatesToConfiguredProvider(t *testing.T) {
	fp := &fakeProvider{operatorToken: "kc-token-123"}

	token, err := getOperatorToken(context.Background(), testSettings(t, nil), fp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "kc-token-123" {
		t.Fatalf("unexpected token: %q", token)
	}
	if fp.calls != 1 {
		t.Fatalf("expected GetOperatorToken called once, got %d", fp.calls)
	}
}

func TestGetOperatorTokenRequiresProviderWhenNotSpiffe(t *testing.T) {
	settings := testSettings(t, nil)
	_, err := getOperatorToken(context.Background(), settings, nil)
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestGetOperatorTokenDispatchesToSpiffeWhenConfigured(t *testing.T) {
	settings := testSettings(t, map[string]string{
		"OPERATOR_IDENTITY_SOURCE": "spiffe",
		"OPERATOR_SPIFFE_AUDIENCE": "myceliam-operator",
	})
	t.Setenv(spiffeEndpointSocketEnv, "unix:///spiffe-workload-api/spire-agent.sock")

	original := fetchSpiffeJWTSVID
	fetchSpiffeJWTSVID = func(ctx context.Context, audience, addr string) (string, error) {
		if audience != "myceliam-operator" {
			t.Errorf("unexpected audience: %q", audience)
		}
		return "spiffe-token-123", nil
	}
	t.Cleanup(func() { fetchSpiffeJWTSVID = original })

	fp := &fakeProvider{}
	token, err := getOperatorToken(context.Background(), settings, fp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "spiffe-token-123" {
		t.Fatalf("unexpected token: %q", token)
	}
	if fp.calls != 0 {
		t.Fatalf("expected the provider's GetOperatorToken not to be called for spiffe identity source")
	}
}

func TestGetOperatorSpiffeTokenRequiresAudience(t *testing.T) {
	t.Setenv(spiffeEndpointSocketEnv, "unix:///spiffe-workload-api/spire-agent.sock")
	settings := testSettings(t, map[string]string{"OPERATOR_IDENTITY_SOURCE": "spiffe"})

	_, err := getOperatorSpiffeToken(context.Background(), settings)
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestGetOperatorSpiffeTokenRequiresSocketEnvVar(t *testing.T) {
	t.Setenv(spiffeEndpointSocketEnv, "")
	settings := testSettings(t, map[string]string{
		"OPERATOR_IDENTITY_SOURCE": "spiffe",
		"OPERATOR_SPIFFE_AUDIENCE": "myceliam-operator",
	})

	_, err := getOperatorSpiffeToken(context.Background(), settings)
	perm, ok := operr.AsPermanent(err)
	if !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
	if !strings.Contains(perm.Error(), "SPIFFE_ENDPOINT_SOCKET") {
		t.Fatalf("expected error mentioning SPIFFE_ENDPOINT_SOCKET, got %v", perm)
	}
}

type fakeSTS struct {
	lastInput *sts.AssumeRoleWithWebIdentityInput
	output    *sts.AssumeRoleWithWebIdentityOutput
	err       error
}

func (f *fakeSTS) AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	f.lastInput = params
	if f.err != nil {
		return nil, f.err
	}
	return f.output, nil
}

func TestGetAWSCredentialsAssumesCorrectRole(t *testing.T) {
	fp := &fakeProvider{operatorToken: "kc-token-123"}

	fake := &fakeSTS{
		output: &sts.AssumeRoleWithWebIdentityOutput{
			Credentials: &types.Credentials{
				AccessKeyId:     awssdk.String("AKIA..."),
				SecretAccessKey: awssdk.String("secret"),
				SessionToken:    awssdk.String("token"),
			},
		},
	}
	original := newSTSClient
	newSTSClient = func() stsAPI { return fake }
	t.Cleanup(func() { newSTSClient = original })

	settings := testSettings(t, nil)

	creds, err := GetAWSCredentials(context.Background(), settings, "111111111111", fp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if awssdk.ToString(fake.lastInput.RoleArn) != "arn:aws:iam::111111111111:role/myceliam-operator" {
		t.Fatalf("unexpected RoleArn: %v", awssdk.ToString(fake.lastInput.RoleArn))
	}
	if awssdk.ToString(fake.lastInput.RoleSessionName) != "myceliam-operator" {
		t.Fatalf("unexpected RoleSessionName: %v", awssdk.ToString(fake.lastInput.RoleSessionName))
	}
	if awssdk.ToString(fake.lastInput.WebIdentityToken) != "kc-token-123" {
		t.Fatalf("unexpected WebIdentityToken: %v", awssdk.ToString(fake.lastInput.WebIdentityToken))
	}
	if creds.AccessKeyID != "AKIA..." || creds.SessionToken != "token" {
		t.Fatalf("unexpected creds: %+v", creds)
	}
}

func TestGetGCPAccessTokenRequiresBootstrapConfig(t *testing.T) {
	settings := testSettings(t, nil)
	_, err := GetGCPAccessToken(context.Background(), settings, &fakeProvider{operatorToken: "kc-token-123"})
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestGetGCPAccessTokenExchangesAndImpersonates(t *testing.T) {
	fp := &fakeProvider{operatorToken: "kc-token-123"}

	var exchangeBody, impersonateBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "generateAccessToken"):
			_ = json.NewDecoder(r.Body).Decode(&impersonateBody)
			_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": "gcp-access-token"})
		default:
			_ = json.NewDecoder(r.Body).Decode(&exchangeBody)
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "federated-token"})
		}
	}))
	defer server.Close()

	origSTSURL, origIAMFmt := gcpSTSTokenURL, gcpIAMCredentialsURLFmt
	gcpSTSTokenURL = server.URL + "/token"
	gcpIAMCredentialsURLFmt = server.URL + "/projects/-/serviceAccounts/%s:generateAccessToken"
	t.Cleanup(func() { gcpSTSTokenURL, gcpIAMCredentialsURLFmt = origSTSURL, origIAMFmt })

	settings := testSettings(t, map[string]string{
		"GCP_OPERATOR_STS_AUDIENCE":          "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/prov",
		"GCP_OPERATOR_SERVICE_ACCOUNT_EMAIL": "myceliam-operator@hub.iam.gserviceaccount.com",
	})

	token, err := GetGCPAccessToken(context.Background(), settings, fp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "gcp-access-token" {
		t.Fatalf("unexpected token: %q", token)
	}
	if exchangeBody["subjectToken"] != "kc-token-123" {
		t.Fatalf("unexpected exchange body: %v", exchangeBody)
	}
	_ = impersonateBody
}

func TestGetGCPAccessTokenSurfacesResponseBodyOnFailure(t *testing.T) {
	fp := &fakeProvider{operatorToken: "svid-jwt-123"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "invalid_request", "error_description": "Invalid audience"}`))
	}))
	defer server.Close()

	origSTSURL := gcpSTSTokenURL
	gcpSTSTokenURL = server.URL
	t.Cleanup(func() { gcpSTSTokenURL = origSTSURL })

	settings := testSettings(t, map[string]string{
		"GCP_OPERATOR_STS_AUDIENCE":          "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/prov",
		"GCP_OPERATOR_SERVICE_ACCOUNT_EMAIL": "myceliam-operator@hub.iam.gserviceaccount.com",
	})

	_, err := GetGCPAccessToken(context.Background(), settings, fp)
	temp, ok := operr.AsTemporary(err)
	if !ok {
		t.Fatalf("expected *operr.Temporary, got %v", err)
	}
	if !strings.Contains(temp.Error(), "Invalid audience") {
		t.Fatalf("expected error mentioning response body, got %v", temp)
	}
}
