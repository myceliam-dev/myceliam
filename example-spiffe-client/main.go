// example-spiffe-client is the SPIFFE-identified counterpart to
// example-oidc-client: it proves a SPIFFE workload (not just a
// Keycloak-issued client) can federate through myceliam into real AWS/GCP
// credentials. The only real difference from example-oidc-client is how the
// JWT is obtained —
// here via the local SPIRE agent's Workload API (go-spiffe/v2), instead of a
// Keycloak client_credentials grant. Everything downstream (AssumeRoleWithWebIdentity,
// GCP's STS-then-impersonate exchange) is identical.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	awsAccountID = "<aws-account-id>"
	awsRolesCSV  = "s3-role-a,s3-role-b" // every role listed for this account in the summer namespace's AwsAccessProfile
	awsRegion    = "us-east-1"

	// awsAudience/gcpAudience must match what myceliam actually configured
	// on the AWS role trust condition / GCP WLI provider's allowedAudiences
	// for this namespace — see cloudmodels.ParseCloudFederationSpecs's own
	// doc comment for the <cloud>-<namespace>[-<sa>] convention.
	awsAudience = "aws-morel-morel-spiffe-sa"
	gcpAudience = "gcp-morel"

	// gcpSTSAudience names the WLI provider gcpap-summer (well, whatever the
	// GcpAccessProfile in "summer" is named — the provider ID doesn't depend
	// on that, only on cluster-id+namespace+kind) federates into:
	// //iam.googleapis.com/projects/{number}/locations/global/workloadIdentityPools/{pool}/providers/{provider}
	// Update the provider ID segment if MYCELIAM_CLUSTER_ID on this cluster
	// ever changes.
	gcpSTSAudience   = "//iam.googleapis.com/projects/<gcp-project-number>/locations/global/workloadIdentityPools/myceliam-operator/providers/demo-morel-spiffe"
	gcpTargetSAEmail = "app-default@<your-gcp-project-id>.iam.gserviceaccount.com"
	gcpProjectID     = "<your-gcp-project-id>"
)

func main() {
	ctx := context.Background()

	endpoint := mustEnv("SPIFFE_ENDPOINT_SOCKET")

	// Separate single-audience SVIDs, not one combined multi-aud token: AWS
	// rejects a multi-value aud claim outright unless an azp claim
	// disambiguates it, and SPIFFE JWT-SVIDs carry no azp at all (unlike
	// Keycloak-issued tokens, which always do) — see fetchJWTSVID's doc
	// comment.
	fmt.Println("\n=== AWS S3 buckets ===")
	awsJWT, err := fetchJWTSVID(ctx, endpoint, awsAudience)
	if err != nil {
		log.Fatalf("fetching AWS-audience JWT-SVID from SPIRE Workload API: %v", err)
	}
	log.Println("aws svid-jwt", awsJWT)
	for _, roleName := range strings.Split(awsRolesCSV, ",") {
		if err := listAWSBuckets(ctx, awsJWT, roleName); err != nil {
			log.Printf("role %s: %v", roleName, err)
		}
	}

	fmt.Println("\n=== GCP Cloud Storage buckets ===")
	gcpJWT, err := fetchJWTSVID(ctx, endpoint, gcpAudience)
	if err != nil {
		log.Fatalf("fetching GCP-audience JWT-SVID from SPIRE Workload API: %v", err)
	}
	log.Println("gcp svid-jwt", gcpJWT)
	if err := listGCPBuckets(ctx, gcpJWT); err != nil {
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

// fetchJWTSVID fetches a JWT-SVID for a single audience. Deliberately not
// combined into one multi-audience token the way the Keycloak-issued demo
// app combines its two scopes into one token: AWS rejects a JWT whose aud
// claim has more than one value unless an azp claim disambiguates it (the
// same azp-folding behavior discovered for Keycloak tokens, which always
// carry azp) — SPIFFE JWT-SVIDs have no azp concept at all, so a combined
// SVID here would get rejected outright by AssumeRoleWithWebIdentity with
// "Token audience contains more than one audience while authorized party is
// not present".
func fetchJWTSVID(ctx context.Context, socketAddr, audience string) (string, error) {
	svid, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	}, workloadapi.WithAddr(socketAddr))
	if err != nil {
		return "", err
	}
	return svid.Marshal(), nil
}

func listAWSBuckets(ctx context.Context, jwt, roleName string) error {
	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", awsAccountID, roleName)

	stsClient := sts.NewFromConfig(aws.Config{
		Region:      awsRegion,
		Credentials: aws.AnonymousCredentials{}, // AssumeRoleWithWebIdentity needs no ambient credentials
	})
	assumed, err := stsClient.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		RoleSessionName:  aws.String("morel-spiffe-sa-demo"),
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

func listGCPBuckets(ctx context.Context, jwt string) error {
	federatedToken, err := gcpSTSExchange(ctx, jwt)
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

func gcpSTSExchange(ctx context.Context, jwt string) (string, error) {
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
