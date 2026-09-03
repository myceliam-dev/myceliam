// Package aws ports pythonoperator/src/myceliam/cloud_providers/aws.py: AWS
// IdP federation (myceliam.io/aws-access-profile label). Registers each
// namespace's Keycloak realm (or, for spiffe ServiceAccounts, the SPIRE OIDC
// Discovery Provider) as an IAM OIDC identity provider in every account
// listed in the referenced AwsAccessProfile. The IdP itself is one-per-
// namespace-per-account; its ClientIDList grows as each SA in that namespace
// opts in — the shared `myceliam-<namespace>` audience up front, plus that
// SA's own name once it reconciles. Both are needed: AWS matches ClientIDList
// against the token's `aud` claim *and* its `azp` claim, which Keycloak
// always sets to the client_id — so the SA's own name lands there
// automatically, no extra mapper required.
//
// Registration only — this does not create the IAM Role/trust-policy that
// would actually grant permissions once federated; that's left to account
// owners.
package aws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"myceliam/internal/operr"
)

const idpCallDelay = 30 * time.Second

// Credentials are short-lived AWS credentials obtained by exchanging the
// operator's own identity via AssumeRoleWithWebIdentity — the Go equivalent
// of operator_identity.py's AwsCredentials dataclass. Defined here (rather
// than in the operatoridentity package that produces them) because this
// package's calls are the only thing that consumes them; operatoridentity
// imports this type instead of the other way around, so there's no import
// cycle between "the package that fetches credentials" and "the package that
// uses them."
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// iamAPI is the subset of *iam.Client this package calls, matching its real
// method signatures exactly so *iam.Client satisfies it with no glue code.
// The seam lets tests inject a fake instead of talking to AWS.
type iamAPI interface {
	GetOpenIDConnectProvider(ctx context.Context, params *iam.GetOpenIDConnectProviderInput, optFns ...func(*iam.Options)) (*iam.GetOpenIDConnectProviderOutput, error)
	CreateOpenIDConnectProvider(ctx context.Context, params *iam.CreateOpenIDConnectProviderInput, optFns ...func(*iam.Options)) (*iam.CreateOpenIDConnectProviderOutput, error)
	AddClientIDToOpenIDConnectProvider(ctx context.Context, params *iam.AddClientIDToOpenIDConnectProviderInput, optFns ...func(*iam.Options)) (*iam.AddClientIDToOpenIDConnectProviderOutput, error)
	RemoveClientIDFromOpenIDConnectProvider(ctx context.Context, params *iam.RemoveClientIDFromOpenIDConnectProviderInput, optFns ...func(*iam.Options)) (*iam.RemoveClientIDFromOpenIDConnectProviderOutput, error)
	DeleteOpenIDConnectProvider(ctx context.Context, params *iam.DeleteOpenIDConnectProviderInput, optFns ...func(*iam.Options)) (*iam.DeleteOpenIDConnectProviderOutput, error)
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	UpdateAssumeRolePolicy(ctx context.Context, params *iam.UpdateAssumeRolePolicyInput, optFns ...func(*iam.Options)) (*iam.UpdateAssumeRolePolicyOutput, error)
}

// newIAMClient is a package-level factory var so tests can swap in a fake —
// the Go equivalent of the Python suite's mocker.patch("...aws.boto3.client").
var newIAMClient = func(creds Credentials) iamAPI {
	return iam.NewFromConfig(awssdk.Config{
		// IAM is a global service, but SigV4 signing still needs *a* region;
		// AWS always resolves IAM calls to us-east-1 regardless of caller
		// location, matching boto3's own default for global services.
		Region: "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(
			creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken,
		),
	})
}

func providerARN(accountID, issuerURL string) string {
	hostAndPath := strings.TrimPrefix(strings.TrimPrefix(issuerURL, "https://"), "http://")
	return fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", accountID, hostAndPath)
}

func isNoSuchEntity(err error) bool {
	var nse *types.NoSuchEntityException
	return errors.As(err, &nse)
}

// EnsureIdp ensures an IAM OIDC provider exists in accountID for issuerURL,
// with every entry in audiences present in its ClientIDList. Idempotent:
// updates rather than duplicates, and only adds whichever entries are missing.
func EnsureIdp(ctx context.Context, accountID, issuerURL string, audiences []string, creds Credentials) error {
	client := newIAMClient(creds)
	arn := providerARN(accountID, issuerURL)

	out, err := client.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: awssdk.String(arn),
	})
	if err == nil {
		existing := make(map[string]bool, len(out.ClientIDList))
		for _, a := range out.ClientIDList {
			existing[a] = true
		}
		for _, audience := range audiences {
			if existing[audience] {
				continue
			}
			if _, err := client.AddClientIDToOpenIDConnectProvider(ctx, &iam.AddClientIDToOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: awssdk.String(arn),
				ClientID:                 awssdk.String(audience),
			}); err != nil {
				return operr.Temporaryf(idpCallDelay, "Error adding audience %s to OIDC provider %s: %v", audience, arn, err)
			}
		}
		return nil
	}
	if !isNoSuchEntity(err) {
		return operr.Temporaryf(idpCallDelay, "Error checking OIDC provider '%s' in account %s: %v", arn, accountID, err)
	}

	if _, err := client.CreateOpenIDConnectProvider(ctx, &iam.CreateOpenIDConnectProviderInput{
		Url:          awssdk.String(issuerURL),
		ClientIDList: audiences,
	}); err != nil {
		return operr.Temporaryf(idpCallDelay, "Error creating OIDC provider for '%s' in account %s: %v", issuerURL, accountID, err)
	}
	return nil
}

// RemoveAudience removes a single audience (e.g. an SA's own name) from the
// IdP's ClientIDList once that SA is no longer part of this federation —
// label removed, or the SA itself deleted. Leaves the provider itself intact:
// it's shared across every SA in the namespace targeting this account, the
// same way EnsureIdp only ever adds to it.
func RemoveAudience(ctx context.Context, accountID, issuerURL, audience string, creds Credentials) error {
	client := newIAMClient(creds)
	arn := providerARN(accountID, issuerURL)

	_, err := client.RemoveClientIDFromOpenIDConnectProvider(ctx, &iam.RemoveClientIDFromOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: awssdk.String(arn),
		ClientID:                 awssdk.String(audience),
	})
	if err != nil {
		if isNoSuchEntity(err) {
			return nil
		}
		return operr.Temporaryf(idpCallDelay, "Error removing audience '%s' from OIDC provider '%s' in account %s: %v", audience, arn, accountID, err)
	}
	return nil
}

func DeleteIdp(ctx context.Context, accountID, issuerURL string, creds Credentials) error {
	client := newIAMClient(creds)
	arn := providerARN(accountID, issuerURL)

	_, err := client.DeleteOpenIDConnectProvider(ctx, &iam.DeleteOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: awssdk.String(arn),
	})
	if err != nil {
		if isNoSuchEntity(err) {
			return nil
		}
		return operr.Temporaryf(idpCallDelay, "Error deleting OIDC provider '%s' in account %s: %v", arn, accountID, err)
	}
	return nil
}

// trustPolicyDocument/trustPolicyStatement are a minimal, order-preserving
// model of an IAM trust policy (AssumeRolePolicyDocument) — just enough
// structure to find-and-replace myceliam's own statement (identified by a
// stable Sid) without disturbing any other statement a role's trust policy
// might already carry (e.g. one trusting ec2.amazonaws.com, or another
// namespace's entity).
type trustPolicyDocument struct {
	Version   string                 `json:"Version"`
	Statement []trustPolicyStatement `json:"Statement"`
}

type trustPolicyStatement struct {
	Sid       string                    `json:"Sid,omitempty"`
	Effect    string                    `json:"Effect"`
	Principal map[string]any            `json:"Principal"`
	Action    any                       `json:"Action"`
	Condition map[string]map[string]any `json:"Condition,omitempty"`
}

// roleTrustStatementID derives a stable, alphanumeric-only Sid (IAM's Sid
// character set forbids hyphens/slashes, which namespace and SPIFFE-ID
// values routinely contain) identifying "this entity's" statement within a
// role's trust policy, so repeated EnsureRoleTrust/RemoveRoleTrust calls for
// the same entity find and update/remove the same statement rather than
// accumulating duplicates.
func roleTrustStatementID(issuerURL, subjectClaim, subjectValue string) string {
	sum := sha256.Sum256([]byte(issuerURL + "|" + subjectClaim + "|" + subjectValue))
	return "myceliam" + hex.EncodeToString(sum[:])[:16]
}

func decodeTrustPolicy(raw *string) (trustPolicyDocument, error) {
	doc := trustPolicyDocument{Version: "2012-10-17"}
	if raw == nil || *raw == "" {
		return doc, nil
	}
	// IAM returns AssumeRolePolicyDocument URL-encoded.
	decoded, err := url.QueryUnescape(*raw)
	if err != nil {
		return doc, fmt.Errorf("decoding trust policy: %w", err)
	}
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return doc, fmt.Errorf("parsing trust policy JSON: %w", err)
	}
	return doc, nil
}

// upsertStatement replaces the statement matching stmt.Sid in place, or
// appends it if no statement with that Sid exists yet. Returns false (no
// write needed) if an identical statement is already present.
func upsertStatement(doc *trustPolicyDocument, stmt trustPolicyStatement) bool {
	for i, existing := range doc.Statement {
		if existing.Sid == stmt.Sid {
			if reflect.DeepEqual(existing, stmt) {
				return false
			}
			doc.Statement[i] = stmt
			return true
		}
	}
	doc.Statement = append(doc.Statement, stmt)
	return true
}

// removeStatement removes the statement with the given Sid, if present.
// Returns false (no write needed) if it wasn't there to begin with.
func removeStatement(doc *trustPolicyDocument, sid string) bool {
	for i, existing := range doc.Statement {
		if existing.Sid == sid {
			doc.Statement = append(doc.Statement[:i], doc.Statement[i+1:]...)
			return true
		}
	}
	return false
}

// EnsureRoleTrust ensures roleName's trust policy in accountID includes a
// statement allowing the entity identified by (issuerURL, audience,
// subjectClaim=subjectValue) to assume it via AssumeRoleWithWebIdentity,
// without disturbing any other existing trust statement. subjectClaim is
// "azp" for Keycloak-issued tokens (the SA name) or "sub" for SPIFFE-issued
// JWT-SVIDs (the full SPIFFE ID) — see models.SpiffeIDAnnotation's doc
// comment for why SPIFFE can't use azp.
//
// roleName must already exist — myceliam never creates IAM roles, only
// manages trust on ones account owners provisioned out-of-band (same
// registration-only model as the IdP itself).
func EnsureRoleTrust(ctx context.Context, accountID, roleName, issuerURL, audience, subjectClaim, subjectValue string, creds Credentials) error {
	client := newIAMClient(creds)

	out, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: awssdk.String(roleName)})
	if err != nil {
		if isNoSuchEntity(err) {
			return operr.Permanentf(
				"IAM role '%s' does not exist in account %s — roles must be pre-provisioned "+
					"out-of-band, myceliam never creates them.", roleName, accountID,
			)
		}
		return operr.Temporaryf(idpCallDelay, "Error reading IAM role '%s' in account %s: %v", roleName, accountID, err)
	}

	doc, err := decodeTrustPolicy(out.Role.AssumeRolePolicyDocument)
	if err != nil {
		return operr.Temporaryf(idpCallDelay, "Error decoding trust policy for role '%s' in account %s: %v", roleName, accountID, err)
	}

	hostAndPath := strings.TrimPrefix(strings.TrimPrefix(issuerURL, "https://"), "http://")

	// Whether Keycloak issues aud as a single string or a JSON array depends
	// on which client scopes end up attached to the token (it appends its own
	// default "account" audience whenever the "roles" scope's audience-resolve
	// mapper is in play) — not something this code can assume either way. And
	// per the OIDC spec, a multi-valued aud requires the token to carry azp
	// identifying the true intended recipient; AWS's OIDC federation follows
	// that spec exactly, resolving its own `:aud` policy-context key from azp
	// whenever the raw aud claim is an array, rather than exposing the array
	// itself. So depending on token shape, AWS may expose either our custom
	// audience string (clean single-value aud) or subjectValue itself
	// (multi-value, azp-folded) under `:aud` — never both, and never a
	// separate `:azp` key. ForAnyValue:StringEquals against both acceptable
	// values on the policy side handles either shape without needing to know
	// which one a given deployment produces. SPIFFE JWT-SVIDs
	// (subjectClaim=="sub") carry no azp and a single-valued aud, so they
	// don't hit this and keep the straightforward aud+sub check.
	condition := map[string]map[string]any{
		// []any, not []string: upsertStatement compares this against a
		// json.Unmarshal-decoded existing statement via reflect.DeepEqual,
		// and a decoded JSON array always comes back as []any — a []string
		// here would never match, defeating idempotency on every reconcile.
		"ForAnyValue:StringEquals": {
			hostAndPath + ":aud": []any{audience, subjectValue},
		},
	}
	if subjectClaim != "azp" {
		condition = map[string]map[string]any{
			"StringEquals": {
				hostAndPath + ":aud":             audience,
				hostAndPath + ":" + subjectClaim: subjectValue,
			},
		}
	}
	stmt := trustPolicyStatement{
		Sid:       roleTrustStatementID(issuerURL, subjectClaim, subjectValue),
		Effect:    "Allow",
		Principal: map[string]any{"Federated": providerARN(accountID, issuerURL)},
		Action:    "sts:AssumeRoleWithWebIdentity",
		Condition: condition,
	}

	if !upsertStatement(&doc, stmt) {
		return nil
	}

	encoded, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encoding trust policy for role %q: %w", roleName, err)
	}
	if _, err := client.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		RoleName:       awssdk.String(roleName),
		PolicyDocument: awssdk.String(string(encoded)),
	}); err != nil {
		return operr.Temporaryf(idpCallDelay, "Error updating trust policy for role '%s' in account %s: %v", roleName, accountID, err)
	}
	return nil
}

// RemoveRoleTrust removes the trust-policy statement EnsureRoleTrust added
// for this entity, leaving every other statement on roleName's trust policy
// untouched. No-op if the role or the statement is already gone.
func RemoveRoleTrust(ctx context.Context, accountID, roleName, issuerURL, subjectClaim, subjectValue string, creds Credentials) error {
	client := newIAMClient(creds)

	out, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: awssdk.String(roleName)})
	if err != nil {
		if isNoSuchEntity(err) {
			return nil
		}
		return operr.Temporaryf(idpCallDelay, "Error reading IAM role '%s' in account %s: %v", roleName, accountID, err)
	}

	doc, err := decodeTrustPolicy(out.Role.AssumeRolePolicyDocument)
	if err != nil {
		return operr.Temporaryf(idpCallDelay, "Error decoding trust policy for role '%s' in account %s: %v", roleName, accountID, err)
	}

	sid := roleTrustStatementID(issuerURL, subjectClaim, subjectValue)
	if !removeStatement(&doc, sid) {
		return nil
	}

	encoded, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encoding trust policy for role %q: %w", roleName, err)
	}
	if _, err := client.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		RoleName:       awssdk.String(roleName),
		PolicyDocument: awssdk.String(string(encoded)),
	}); err != nil {
		return operr.Temporaryf(idpCallDelay, "Error updating trust policy for role '%s' in account %s: %v", roleName, accountID, err)
	}
	return nil
}
