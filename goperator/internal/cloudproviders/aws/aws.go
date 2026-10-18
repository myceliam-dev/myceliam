// Package aws ports pythonoperator/src/myceliam/cloud_providers/aws.py: AWS
// IdP federation (myceliam.io/aws-access-profile label). Registers each
// namespace's Keycloak realm (or, for spiffe ServiceAccounts, the SPIRE OIDC
// Discovery Provider) as an IAM OIDC identity provider in every account
// listed in the referenced AwsAccessProfile. The IdP itself is one-per-
// namespace-per-account; its ClientIDList grows as each SA in that namespace
// opts in — the shared `myceliam-<namespace>` audience up front, plus that
// SA's own name once it reconciles, plus (for Auth0) its own
// dynamically-assigned client_id, since that — not the SA name — is what
// lands in azp there. Both audience and azp/client_id are needed: AWS
// matches ClientIDList against the token's `aud` claim *and* its `azp`
// claim when present. For Keycloak the SA's own name lands in azp
// automatically (client_id fixed to it by construction, no extra mapper
// required); Auth0 has no custom-client_id support, so its azp is unrelated
// to the SA name and must be registered explicitly — see
// oidc.Provider.EnsureAccessScope's azpValue return.
//
// Registration and trust only — EnsureRoleTrust creates roleName if it
// doesn't exist yet (trust policy only, no permissions attached), but this
// package never attaches or implies an IAM permissions policy. What a
// federated identity can actually *do* once trusted is still entirely up to
// whatever policy an account owner attaches to the role themselves.
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
	CreateRole(ctx context.Context, params *iam.CreateRoleInput, optFns ...func(*iam.Options)) (*iam.CreateRoleOutput, error)
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

// DeleteIdp deletes the IAM OIDC provider for issuerURL in accountID
// outright. No-op if it's already gone. protectedClientIDs are client_ids
// that must never be lost — typically the operator's own bootstrap
// identifier for whichever provider it uses (see
// cloudmodels.CloudFederationSpec.IssuerShared's doc comment for the real
// live incident this guards against): if the provider's current
// ClientIDList still contains any of them, deletion is refused as a safe
// no-op rather than an error, since this isn't a failure — something else
// still legitimately needs this provider to exist. Pass nil/empty when
// there's nothing to protect.
//
// This alone doesn't make DeleteIdp safe to call for a provider whose
// issuer might be shared across namespaces (Auth0) — callers there should
// prefer RemoveAudience and never call this at all; this check is a second,
// coarser line of defense specifically for the operator's own identity,
// not a substitute for that caller-side judgment.
func DeleteIdp(ctx context.Context, accountID, issuerURL string, protectedClientIDs []string, creds Credentials) error {
	client := newIAMClient(creds)
	arn := providerARN(accountID, issuerURL)

	if len(protectedClientIDs) > 0 {
		out, err := client.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{
			OpenIDConnectProviderArn: awssdk.String(arn),
		})
		if err != nil && !isNoSuchEntity(err) {
			return operr.Temporaryf(idpCallDelay, "Error checking OIDC provider '%s' in account %s before delete: %v", arn, accountID, err)
		}
		if err == nil {
			existing := make(map[string]bool, len(out.ClientIDList))
			for _, c := range out.ClientIDList {
				existing[c] = true
			}
			for _, protected := range protectedClientIDs {
				if existing[protected] {
					return nil
				}
			}
		}
	}

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
// "azp" for Keycloak-issued tokens (the SA name), the
// self-issued myceliam_service_account claim for Auth0 (see
// cloudmodels.OidcSubjectClaim), or "sub" for SPIFFE-issued JWT-SVIDs (the
// full SPIFFE ID) — see models.SpiffeIDAnnotation's doc comment for why
// SPIFFE can't use azp.
//
// azpValue is the value the token actually carries as azp — which AWS STS
// folds into its own `:aud` policy-context key whenever the token carries
// azp at all, confirmed live to happen even for a single-string (non-array)
// raw aud claim, overriding it unconditionally rather than only in the
// multi-valued case this package previously assumed. For Keycloak,
// azpValue is always subjectValue itself (azp fixed to the SA name by
// construction — see oidc.Provider.EnsureAccessScope's doc comment), so
// passing subjectValue again there is correct and changes nothing. Auth0 is
// the one case where azpValue differs from both audience and subjectValue
// (its own dynamically-assigned client_id, unrelated to either) — pass ""
// for callers that know their provider never sets azp at all (SPIFFE).
//
// sharedAudience must be true whenever audience is not already unique to
// this one entity — see the condition-building comment
// below for why this, not subjectClaim's literal name, is what decides which
// matching strategy is safe.
//
// subjectClaimViaSessionTag is cloudmodels.CloudFederationSpec's field of
// the same name — true (Auth0 only, today) when subjectClaim isn't usable as
// a direct "<issuer>:<subjectClaim>" trust-policy condition key (confirmed
// live: AWS never matches a custom claim injected at runtime by an Action
// that way) and must instead be matched via "aws:RequestTag/<subjectClaim>"
// plus the sts:TagSession action, relying on that same claim also being
// projected into the token's "https://aws.amazon.com/tags" session-tags
// claim. See CloudFederationSpec's own doc comment for the full story.
//
// If roleName doesn't exist yet, EnsureRoleTrust creates it with this trust
// statement as its entire initial trust policy — myceliam still never
// attaches or implies any permissions policy, so a freshly-created role can
// assume-into but do nothing until an account owner attaches one; this is
// creating the *principal*, not authorizing it, the same registration-only
// boundary myceliam already draws around every other AWS/GCP resource (see
// [Design principles](#design-principles)). Confirmed as the right default
// live: requiring every role to be pre-provisioned out-of-band meant a
// brand-new role had to start from *some* trust policy just to satisfy AWS's
// "a role can't be created with an empty trust policy" rule, which in
// practice meant hand-authoring the exact same web-identity statement this
// function would write anyway. Existing roles are untouched beyond the one
// statement this function manages, exactly as before.
func EnsureRoleTrust(ctx context.Context, accountID, roleName, issuerURL, audience, subjectClaim, subjectValue, azpValue string, sharedAudience, subjectClaimViaSessionTag bool, creds Credentials) error {
	client := newIAMClient(creds)

	hostAndPath := strings.TrimPrefix(strings.TrimPrefix(issuerURL, "https://"), "http://")

	// AWS's OIDC federation resolves its own `:aud` policy-context key from
	// azp whenever the token carries azp at all — confirmed live to happen
	// unconditionally, not only (as this package previously assumed) when
	// the raw aud claim is a JSON array. So `:aud` may end up being our
	// custom audience string (no azp on the token — SPIFFE) or azpValue
	// (azp present — every OIDC provider's client-credentials tokens, in
	// practice) — never both, and never a separate `:azp` key.
	// ForAnyValue:StringEquals against every acceptable value handles
	// whichever shape a given deployment produces without needing to know
	// which one upfront.
	//
	// Matching `:aud` against this OR-list alone only proves identity when
	// audience is already unique to this one SA *and* azpValue is too
	// (Keycloak's convention: subjectClaim=="azp", azpValue==subjectValue,
	// audience per-SA) — so no separate subjectClaim condition is needed to
	// compensate there. Everywhere else (Auth0, whose azpValue is its own
	// client_id, unrelated to subjectValue, and whose audience is
	// namespace-shared; SPIFFE) a shared or azp-unrelated audience no longer
	// proves identity by itself, so the strict subjectClaim==subjectValue
	// condition below is additionally required — ANDed with the `:aud`
	// OR-list, not a replacement for it, since AWS still exposes `:aud` as
	// azpValue and the policy must accept whatever it actually sends.
	audMatches := []any{audience}
	if azpValue != "" && azpValue != audience {
		audMatches = append(audMatches, azpValue)
	}
	condition := map[string]map[string]any{
		// []any, not []string: upsertStatement compares this against a
		// json.Unmarshal-decoded existing statement via reflect.DeepEqual,
		// and a decoded JSON array always comes back as []any — a []string
		// here would never match, defeating idempotency on every reconcile.
		"ForAnyValue:StringEquals": {
			hostAndPath + ":aud": audMatches,
		},
	}
	if subjectClaim != "azp" || sharedAudience {
		// subjectClaimViaSessionTag (Auth0): the claim is only real to AWS
		// via the session-tags detour — confirmed live that
		// "<issuer>:myceliam_service_account" never matches, while
		// "aws:RequestTag/myceliam_service_account" does, given the
		// tenant-wide Action projects the same value into the token's
		// "https://aws.amazon.com/tags" claim. Every other provider's
		// subjectClaim is a normal, provider-discoverable claim, matched
		// directly against the issuer's own policy-context namespace.
		subjectKey := hostAndPath + ":" + subjectClaim
		if subjectClaimViaSessionTag {
			subjectKey = "aws:RequestTag/" + subjectClaim
		}
		condition["ForAnyValue:StringEquals"][subjectKey] = subjectValue
	}
	// []any, not []string — same DeepEqual/idempotency reasoning as
	// Condition above. sts:TagSession is only granted alongside
	// subjectClaimViaSessionTag: that's the one case whose identity proof
	// actually depends on the token's session tags being applied, and
	// AssumeRoleWithWebIdentity requires the action whenever the token
	// carries the "https://aws.amazon.com/tags" claim at all — confirmed
	// live that omitting it produces a generic AccessDenied, not a
	// TagSession-specific error.
	action := []any{"sts:AssumeRoleWithWebIdentity"}
	if subjectClaimViaSessionTag {
		action = append(action, "sts:TagSession")
	}
	stmt := trustPolicyStatement{
		Sid:       roleTrustStatementID(issuerURL, subjectClaim, subjectValue),
		Effect:    "Allow",
		Principal: map[string]any{"Federated": providerARN(accountID, issuerURL)},
		Action:    action,
		Condition: condition,
	}

	out, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: awssdk.String(roleName)})
	if err != nil {
		if !isNoSuchEntity(err) {
			return operr.Temporaryf(idpCallDelay, "Error reading IAM role '%s' in account %s: %v", roleName, accountID, err)
		}
		encoded, err := json.Marshal(trustPolicyDocument{Version: "2012-10-17", Statement: []trustPolicyStatement{stmt}})
		if err != nil {
			return fmt.Errorf("encoding initial trust policy for new role %q: %w", roleName, err)
		}
		if _, err := client.CreateRole(ctx, &iam.CreateRoleInput{
			RoleName:                 awssdk.String(roleName),
			AssumeRolePolicyDocument: awssdk.String(string(encoded)),
			Description:              awssdk.String("Created by myceliam to trust OIDC/SPIFFE federation. myceliam manages trust only - attach a permissions policy separately to grant it any actual access."),
		}); err != nil {
			return operr.Temporaryf(idpCallDelay, "Error creating IAM role '%s' in account %s: %v", roleName, accountID, err)
		}
		return nil
	}

	doc, err := decodeTrustPolicy(out.Role.AssumeRolePolicyDocument)
	if err != nil {
		return operr.Temporaryf(idpCallDelay, "Error decoding trust policy for role '%s' in account %s: %v", roleName, accountID, err)
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
