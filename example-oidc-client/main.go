// example-oidc-client is a small workload that proves myceliam's federated
// identity actually works end to end, from a real ServiceAccount's own
// perspective (not the operator's): it fetches the Keycloak-issued JWT for
// gosa-secret, federates it into both AWS roles listed in awsap-demo-ns1 (via
// AssumeRoleWithWebIdentity) and the GCP service account listed in
// gcpap-demo-ns1 (via GCP's STS-then-impersonate flow), and lists buckets
// with the resulting short-lived credentials.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	awsAccountID = "<aws-account-id>"
	awsRolesCSV  = "s3-role-a,s3-role-b" // every role listed for this account in awsap-demo-ns1
	awsRegion    = "us-east-1"

	gcpTargetSAEmail = "app-default@<your-gcp-project-id>.iam.gserviceaccount.com"
	gcpProjectID     = "<your-gcp-project-id>"
)

func main() {
	ctx := context.Background()
	clientID := mustEnv("KEYCLOAK_CLIENT_ID")
	// Read from the same myceliam-managed credentials secret this
	// ServiceAccount already has, rather than hardcoding a realm name here —
	// the realm is cluster-prefixed (see config.Settings.ClusterID) and
	// would otherwise go stale every time that changes.
	issuer := mustEnv("KEYCLOAK_ISSUER")
	// The GCP WLI provider name is also cluster-prefixed (same reason), so
	// this comes from the deployment's env rather than being hardcoded —
	// lets one image serve multiple clusters without editing source per target.
	gcpSTSAudience := mustEnv("GCP_STS_AUDIENCE")
	// Scope names are per-SA (see cloudmodels.ParseCloudFederationSpecs:
	// "<cloud>-<namespace>-<sa>"), so this is derived from clientID rather
	// than hardcoded — lets the same binary run as any clienttype=secret/
	// signedjwt ServiceAccount in demo-ns1, not just one specific name.
	scope := fmt.Sprintf("aws-portobello-%s gcp-portobello-%s", clientID, clientID)

	// Auto-detects like the operator itself does for its own credential
	// (myceliam-keycloak-secret vs myceliam-keycloak-keypair): a client
	// secret if present, otherwise a mounted signedjwt keypair.
	var jwt string
	var err error
	if clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET"); clientSecret != "" {
		jwt, err = getKeycloakToken(ctx, issuer, clientID, clientSecret, scope)
	} else {
		certPath := mustEnv("KEYCLOAK_TLS_CERT_PATH")
		keyPath := mustEnv("KEYCLOAK_TLS_KEY_PATH")
		jwt, err = getKeycloakTokenSignedJWT(issuer, clientID, certPath, keyPath, scope)
	}
	if err != nil {
		log.Fatalf("obtaining Keycloak token for %s: %v", clientID, err)
	}
	log.Printf("obtained Keycloak-issued JWT for client_id=%s (azp claim)", clientID)
	log.Println("scope:", scope)
	log.Println("access token:", jwt)

	fmt.Println("\n=== AWS S3 buckets ===")
	for _, roleName := range strings.Split(awsRolesCSV, ",") {
		if err := listAWSBuckets(ctx, jwt, roleName); err != nil {
			log.Printf("role %s: %v", roleName, err)
		}
	}

	fmt.Println("\n=== GCP Cloud Storage buckets ===")
	if err := listGCPBuckets(ctx, jwt, gcpSTSAudience); err != nil {
		log.Printf("gcp: %v", err)
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing required env var %s", key)
	}
	return v
}

func getKeycloakToken(ctx context.Context, issuer, clientID, clientSecret, scope string) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {scope},
	}
	tokenURL := issuer + "/protocol/openid-connect/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("token request failed: %d %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("no access_token in response: %s", body)
	}
	return result.AccessToken, nil
}

func listAWSBuckets(ctx context.Context, jwt, roleName string) error {
	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", awsAccountID, roleName)

	stsClient := sts.NewFromConfig(aws.Config{
		Region:      awsRegion,
		Credentials: aws.AnonymousCredentials{}, // AssumeRoleWithWebIdentity needs no ambient credentials
	})
	assumed, err := stsClient.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		RoleSessionName:  aws.String("example-oidc-client"),
		WebIdentityToken: aws.String(jwt),
	})
	if err != nil {
		return fmt.Errorf("AssumeRoleWithWebIdentity(%s): %w", roleARN, err)
	}

	s3Client := s3.NewFromConfig(aws.Config{
		Region: awsRegion,
		Credentials: credentials.NewStaticCredentialsProvider(
			aws.ToString(assumed.Credentials.AccessKeyId),
			aws.ToString(assumed.Credentials.SecretAccessKey),
			aws.ToString(assumed.Credentials.SessionToken),
		),
	})
	out, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("ListBuckets as %s: %w", roleARN, err)
	}

	fmt.Printf("-- role %s (assumed via web identity) --\n", roleName)
	if len(out.Buckets) == 0 {
		fmt.Println("  (no buckets visible to this role)")
	}
	for _, b := range out.Buckets {
		fmt.Printf("  %s\n", aws.ToString(b.Name))
	}
	return nil
}

func listGCPBuckets(ctx context.Context, jwt, gcpSTSAudience string) error {
	federatedToken, err := gcpSTSExchange(ctx, jwt, gcpSTSAudience)
	if err != nil {
		return fmt.Errorf("STS token exchange: %w", err)
	}
	accessToken, err := gcpImpersonate(ctx, federatedToken)
	if err != nil {
		return fmt.Errorf("impersonating %s: %w", gcpTargetSAEmail, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s", gcpProjectID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("list buckets failed: %d %s", resp.StatusCode, body)
	}

	var result struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decoding bucket list: %w", err)
	}

	fmt.Printf("-- service account %s (impersonated via WLI) --\n", gcpTargetSAEmail)
	if len(result.Items) == 0 {
		fmt.Println("  (no buckets in this project, or none visible)")
	}
	for _, item := range result.Items {
		fmt.Printf("  %s\n", item.Name)
	}
	return nil
}

func gcpSTSExchange(ctx context.Context, jwt, gcpSTSAudience string) (string, error) {
	payload, _ := json.Marshal(map[string]any{
		"audience":           gcpSTSAudience,
		"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
		"subjectToken":       jwt,
		"scope":              "https://www.googleapis.com/auth/cloud-platform",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://sts.googleapis.com/v1/token", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("%d %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	return result.AccessToken, nil
}

func gcpImpersonate(ctx context.Context, federatedToken string) (string, error) {
	payload, _ := json.Marshal(map[string]any{"scope": []string{"https://www.googleapis.com/auth/cloud-platform"}})
	impersonateURL := fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken", gcpTargetSAEmail)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, impersonateURL, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+federatedToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("%d %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	return result.AccessToken, nil
}
