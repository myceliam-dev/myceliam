package aws

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

func noSuchEntityErr() error {
	return &types.NoSuchEntityException{Message: awssdk.String("not found")}
}

type fakeIAM struct {
	getOutput *iam.GetOpenIDConnectProviderOutput
	getErr    error

	createCalls []*iam.CreateOpenIDConnectProviderInput
	addCalls    []*iam.AddClientIDToOpenIDConnectProviderInput
	removeCalls []*iam.RemoveClientIDFromOpenIDConnectProviderInput
	deleteCalls []*iam.DeleteOpenIDConnectProviderInput

	removeErr error
	deleteErr error

	getRoleOutput *iam.GetRoleOutput
	getRoleErr    error
	updateCalls   []*iam.UpdateAssumeRolePolicyInput
	updateErr     error

	createRoleCalls []*iam.CreateRoleInput
	createRoleErr   error
}

func (f *fakeIAM) GetOpenIDConnectProvider(ctx context.Context, params *iam.GetOpenIDConnectProviderInput, optFns ...func(*iam.Options)) (*iam.GetOpenIDConnectProviderOutput, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.getOutput, nil
}

func (f *fakeIAM) CreateOpenIDConnectProvider(ctx context.Context, params *iam.CreateOpenIDConnectProviderInput, optFns ...func(*iam.Options)) (*iam.CreateOpenIDConnectProviderOutput, error) {
	f.createCalls = append(f.createCalls, params)
	return &iam.CreateOpenIDConnectProviderOutput{}, nil
}

func (f *fakeIAM) AddClientIDToOpenIDConnectProvider(ctx context.Context, params *iam.AddClientIDToOpenIDConnectProviderInput, optFns ...func(*iam.Options)) (*iam.AddClientIDToOpenIDConnectProviderOutput, error) {
	f.addCalls = append(f.addCalls, params)
	return &iam.AddClientIDToOpenIDConnectProviderOutput{}, nil
}

func (f *fakeIAM) RemoveClientIDFromOpenIDConnectProvider(ctx context.Context, params *iam.RemoveClientIDFromOpenIDConnectProviderInput, optFns ...func(*iam.Options)) (*iam.RemoveClientIDFromOpenIDConnectProviderOutput, error) {
	f.removeCalls = append(f.removeCalls, params)
	if f.removeErr != nil {
		return nil, f.removeErr
	}
	return &iam.RemoveClientIDFromOpenIDConnectProviderOutput{}, nil
}

func (f *fakeIAM) DeleteOpenIDConnectProvider(ctx context.Context, params *iam.DeleteOpenIDConnectProviderInput, optFns ...func(*iam.Options)) (*iam.DeleteOpenIDConnectProviderOutput, error) {
	f.deleteCalls = append(f.deleteCalls, params)
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return &iam.DeleteOpenIDConnectProviderOutput{}, nil
}

func (f *fakeIAM) GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	if f.getRoleErr != nil {
		return nil, f.getRoleErr
	}
	if f.getRoleOutput != nil {
		return f.getRoleOutput, nil
	}
	return &iam.GetRoleOutput{Role: &types.Role{RoleName: params.RoleName}}, nil
}

func (f *fakeIAM) CreateRole(ctx context.Context, params *iam.CreateRoleInput, optFns ...func(*iam.Options)) (*iam.CreateRoleOutput, error) {
	f.createRoleCalls = append(f.createRoleCalls, params)
	if f.createRoleErr != nil {
		return nil, f.createRoleErr
	}
	return &iam.CreateRoleOutput{Role: &types.Role{RoleName: params.RoleName}}, nil
}

func (f *fakeIAM) UpdateAssumeRolePolicy(ctx context.Context, params *iam.UpdateAssumeRolePolicyInput, optFns ...func(*iam.Options)) (*iam.UpdateAssumeRolePolicyOutput, error) {
	f.updateCalls = append(f.updateCalls, params)
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	return &iam.UpdateAssumeRolePolicyOutput{}, nil
}

func withFakeIAM(t *testing.T, fake *fakeIAM) {
	t.Helper()
	original := newIAMClient
	newIAMClient = func(Credentials) iamAPI { return fake }
	t.Cleanup(func() { newIAMClient = original })
}

func testCreds() Credentials {
	return Credentials{AccessKeyID: "AKIA", SecretAccessKey: "secret", SessionToken: "token"}
}

func TestEnsureIdpCreatesWhenAbsent(t *testing.T) {
	fake := &fakeIAM{getErr: noSuchEntityErr()}
	withFakeIAM(t, fake)

	err := EnsureIdp(context.Background(), "111111111111", "https://kc.example.com/realms/demo", []string{"sts.amazonaws.com"}, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.createCalls) != 1 {
		t.Fatalf("expected 1 create call, got %d", len(fake.createCalls))
	}
	call := fake.createCalls[0]
	if awssdk.ToString(call.Url) != "https://kc.example.com/realms/demo" || len(call.ClientIDList) != 1 || call.ClientIDList[0] != "sts.amazonaws.com" {
		t.Fatalf("unexpected create call: %+v", call)
	}
}

func TestEnsureIdpNoopWhenAllAudiencesAlreadyPresent(t *testing.T) {
	fake := &fakeIAM{getOutput: &iam.GetOpenIDConnectProviderOutput{ClientIDList: []string{"sts.amazonaws.com", "my-app"}}}
	withFakeIAM(t, fake)

	err := EnsureIdp(context.Background(), "111111111111", "https://kc.example.com/realms/demo", []string{"sts.amazonaws.com", "my-app"}, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.createCalls) != 0 || len(fake.addCalls) != 0 {
		t.Fatalf("expected no create/add calls, got create=%d add=%d", len(fake.createCalls), len(fake.addCalls))
	}
}

func TestEnsureIdpAddsOnlyMissingAudiences(t *testing.T) {
	fake := &fakeIAM{getOutput: &iam.GetOpenIDConnectProviderOutput{ClientIDList: []string{"sts.amazonaws.com"}}}
	withFakeIAM(t, fake)

	err := EnsureIdp(context.Background(), "111111111111", "https://kc.example.com/realms/demo", []string{"sts.amazonaws.com", "my-app"}, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.addCalls) != 1 || awssdk.ToString(fake.addCalls[0].ClientID) != "my-app" {
		t.Fatalf("unexpected add calls: %+v", fake.addCalls)
	}
	if len(fake.createCalls) != 0 {
		t.Fatalf("expected no create call, got %d", len(fake.createCalls))
	}
}

func TestDeleteIdpDeletesProvider(t *testing.T) {
	fake := &fakeIAM{}
	withFakeIAM(t, fake)

	err := DeleteIdp(context.Background(), "111111111111", "https://kc.example.com/realms/demo", nil, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.deleteCalls) != 1 {
		t.Fatalf("expected 1 delete call, got %d", len(fake.deleteCalls))
	}
	expectedARN := "arn:aws:iam::111111111111:oidc-provider/kc.example.com/realms/demo"
	if awssdk.ToString(fake.deleteCalls[0].OpenIDConnectProviderArn) != expectedARN {
		t.Fatalf("unexpected ARN: %v", awssdk.ToString(fake.deleteCalls[0].OpenIDConnectProviderArn))
	}
}

func TestDeleteIdpNoopWhenAbsent(t *testing.T) {
	fake := &fakeIAM{deleteErr: noSuchEntityErr()}
	withFakeIAM(t, fake)

	if err := DeleteIdp(context.Background(), "111111111111", "https://kc.example.com/realms/demo", nil, testCreds()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDeleteIdpRefusesWhenProtectedClientIDPresent guards a real live
// incident: a shared-issuer IAM OIDC provider (Auth0's tenant-global issuer,
// used by every namespace on that tenant plus the operator's own bootstrap
// identity) was deleted outright once the last workload ServiceAccount in
// ONE namespace stopped needing it — even though the operator's own
// bootstrap client_id was still registered in the same provider's
// ClientIDList. DeleteIdp must refuse (as a safe no-op, not an error) rather
// than delete a provider a protected identity still depends on.
func TestDeleteIdpRefusesWhenProtectedClientIDPresent(t *testing.T) {
	fake := &fakeIAM{getOutput: &iam.GetOpenIDConnectProviderOutput{
		ClientIDList: []string{"my-app", "myceliam-operator"},
	}}
	withFakeIAM(t, fake)

	err := DeleteIdp(context.Background(), "111111111111", "https://dev-ngyf2gzgiq5odql1.us.auth0.com/", []string{"myceliam-operator"}, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.deleteCalls) != 0 {
		t.Fatalf("expected no delete call when a protected client_id is still present, got %d", len(fake.deleteCalls))
	}
}

// TestDeleteIdpProceedsWhenProtectedClientIDAbsent proves the guard doesn't
// over-refuse: a provider whose ClientIDList never contained any protected
// identifier deletes normally.
func TestDeleteIdpProceedsWhenProtectedClientIDAbsent(t *testing.T) {
	fake := &fakeIAM{getOutput: &iam.GetOpenIDConnectProviderOutput{
		ClientIDList: []string{"my-app"},
	}}
	withFakeIAM(t, fake)

	err := DeleteIdp(context.Background(), "111111111111", "https://kc.example.com/realms/demo", []string{"myceliam-operator"}, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.deleteCalls) != 1 {
		t.Fatalf("expected 1 delete call when no protected client_id is present, got %d", len(fake.deleteCalls))
	}
}

func TestRemoveAudienceNoopWhenAbsent(t *testing.T) {
	fake := &fakeIAM{removeErr: noSuchEntityErr()}
	withFakeIAM(t, fake)

	if err := RemoveAudience(context.Background(), "111111111111", "https://kc.example.com/realms/demo", "my-app", testCreds()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func trustPolicyWith(statements ...trustPolicyStatement) *string {
	doc := trustPolicyDocument{Version: "2012-10-17", Statement: statements}
	b, _ := json.Marshal(doc)
	encoded := url.QueryEscape(string(b))
	return &encoded
}

func TestEnsureRoleTrustAddsStatementToEmptyPolicy(t *testing.T) {
	fake := &fakeIAM{getRoleOutput: &iam.GetRoleOutput{Role: &types.Role{
		RoleName:                 awssdk.String("role-a"),
		AssumeRolePolicyDocument: trustPolicyWith(),
	}}}
	withFakeIAM(t, fake)

	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://kc.example.com/realms/demo", "myceliam-demo", "azp", "my-app", "my-app", false, false, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.updateCalls) != 1 {
		t.Fatalf("expected 1 update call, got %d", len(fake.updateCalls))
	}
	var doc trustPolicyDocument
	if err := json.Unmarshal([]byte(awssdk.ToString(fake.updateCalls[0].PolicyDocument)), &doc); err != nil {
		t.Fatalf("unexpected error unmarshaling policy: %v", err)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statement))
	}
	stmt := doc.Statement[0]
	action, _ := stmt.Action.([]any)
	if stmt.Effect != "Allow" || len(action) != 1 || action[0] != "sts:AssumeRoleWithWebIdentity" {
		t.Fatalf("unexpected statement: %+v", stmt)
	}
	// For the azp (Keycloak) path, aud must accept either the custom audience
	// (clean single-value token) or subjectValue (AWS's azp-folded value for
	// a multi-value token) — see EnsureRoleTrust's own doc comment for why
	// either shape is possible depending on which client scopes are attached.
	cond := stmt.Condition["ForAnyValue:StringEquals"]
	if len(stmt.Condition) != 1 {
		t.Fatalf("unexpected condition: %+v", stmt.Condition)
	}
	aud, _ := cond["kc.example.com/realms/demo:aud"].([]any)
	if len(aud) != 2 || aud[0] != "myceliam-demo" || aud[1] != "my-app" {
		t.Fatalf("unexpected aud condition: %+v", cond["kc.example.com/realms/demo:aud"])
	}
}

func TestEnsureRoleTrustSharedAudienceForcesStrictMatch(t *testing.T) {
	fake := &fakeIAM{getRoleOutput: &iam.GetRoleOutput{Role: &types.Role{
		RoleName:                 awssdk.String("role-a"),
		AssumeRolePolicyDocument: trustPolicyWith(),
	}}}
	withFakeIAM(t, fake)

	// sharedAudience=true (e.g. a namespace-shared aud, used by every SA in
	// the namespace) must force the strict aud+azp match even though
	// subjectClaim=="azp" — audience alone no longer proves identity once
	// it's shared. azpValue=="my-app" here too (client_id fixed to the SA
	// name), so the aud OR-list just ends up containing the same value the
	// strict azp key already requires.
	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://sharedaud.example.com/issuer", "aws-cluster1-demo", "azp", "my-app", "my-app", true, false, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc trustPolicyDocument
	if err := json.Unmarshal([]byte(awssdk.ToString(fake.updateCalls[0].PolicyDocument)), &doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cond := doc.Statement[0].Condition["ForAnyValue:StringEquals"]
	aud, _ := cond["sharedaud.example.com/issuer:aud"].([]any)
	if len(aud) != 2 || aud[0] != "aws-cluster1-demo" || aud[1] != "my-app" || cond["sharedaud.example.com/issuer:azp"] != "my-app" {
		t.Fatalf("unexpected condition: %+v", cond)
	}
}

// TestEnsureRoleTrustAcceptsAzpFoldedAudForAuth0 guards a real bug found
// live: Auth0's client-credentials tokens always carry azp set to Auth0's
// own dynamically-assigned client_id (unrelated to both the configured
// audience and to subjectValue, the myceliam_service_account claim's
// value), and AWS STS folds azp into its `:aud` policy-context key
// regardless — so a trust statement matching `:aud` against the literal
// audience string alone always got AccessDenied for Auth0-backed
// ServiceAccounts, even though the myceliam_service_account condition
// (identity proof) was satisfied.
func TestEnsureRoleTrustAcceptsAzpFoldedAudForAuth0(t *testing.T) {
	fake := &fakeIAM{getRoleOutput: &iam.GetRoleOutput{Role: &types.Role{
		RoleName:                 awssdk.String("role-a"),
		AssumeRolePolicyDocument: trustPolicyWith(),
	}}}
	withFakeIAM(t, fake)

	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://dev-ngyf2gzgiq5odql1.us.auth0.com/", "aws-demo-portobello", "myceliam_service_account", "auth0-jwt", "Try9V7oOqq0kOknWl5JuHo6XQ6Ju8a65", true, true, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc trustPolicyDocument
	if err := json.Unmarshal([]byte(awssdk.ToString(fake.updateCalls[0].PolicyDocument)), &doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := doc.Statement[0]
	action, _ := stmt.Action.([]any)
	if len(action) != 2 || action[0] != "sts:AssumeRoleWithWebIdentity" || action[1] != "sts:TagSession" {
		t.Fatalf("expected sts:TagSession alongside sts:AssumeRoleWithWebIdentity, got %+v", stmt.Action)
	}
	cond := stmt.Condition["ForAnyValue:StringEquals"]
	aud, _ := cond["dev-ngyf2gzgiq5odql1.us.auth0.com/:aud"].([]any)
	if len(aud) != 2 || aud[0] != "aws-demo-portobello" || aud[1] != "Try9V7oOqq0kOknWl5JuHo6XQ6Ju8a65" {
		t.Fatalf("expected aud to accept both the configured audience and Auth0's azp client_id, got %+v", cond["dev-ngyf2gzgiq5odql1.us.auth0.com/:aud"])
	}
	// Confirmed live: "<issuer>:myceliam_service_account" never matches (AWS
	// doesn't expose a custom claim injected at runtime by an Action that
	// way) — only "aws:RequestTag/myceliam_service_account" does, via the
	// session-tags detour subjectClaimViaSessionTag=true selects.
	if cond["aws:RequestTag/myceliam_service_account"] != "auth0-jwt" {
		t.Fatalf("expected aws:RequestTag/myceliam_service_account identity condition, got %+v", cond)
	}
	if _, stillPresent := cond["dev-ngyf2gzgiq5odql1.us.auth0.com/:myceliam_service_account"]; stillPresent {
		t.Fatalf("did not expect the non-working issuer-prefixed condition key, got %+v", cond)
	}
}

func TestEnsureRoleTrustSpiffePathChecksAudAndSub(t *testing.T) {
	fake := &fakeIAM{getRoleOutput: &iam.GetRoleOutput{Role: &types.Role{
		RoleName:                 awssdk.String("role-a"),
		AssumeRolePolicyDocument: trustPolicyWith(),
	}}}
	withFakeIAM(t, fake)

	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://spire.example.com", "myceliam-demo", "sub", "spiffe://example.org/ns/demo/sa/my-app", "", false, false, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc trustPolicyDocument
	if err := json.Unmarshal([]byte(awssdk.ToString(fake.updateCalls[0].PolicyDocument)), &doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cond := doc.Statement[0].Condition["ForAnyValue:StringEquals"]
	aud, _ := cond["spire.example.com:aud"].([]any)
	if len(aud) != 1 || aud[0] != "myceliam-demo" || cond["spire.example.com:sub"] != "spiffe://example.org/ns/demo/sa/my-app" {
		t.Fatalf("unexpected condition: %+v", cond)
	}
}

func TestEnsureRoleTrustPreservesOtherStatements(t *testing.T) {
	other := trustPolicyStatement{
		Sid:       "TrustEC2",
		Effect:    "Allow",
		Principal: map[string]any{"Service": "ec2.amazonaws.com"},
		Action:    "sts:AssumeRole",
	}
	fake := &fakeIAM{getRoleOutput: &iam.GetRoleOutput{Role: &types.Role{
		RoleName:                 awssdk.String("role-a"),
		AssumeRolePolicyDocument: trustPolicyWith(other),
	}}}
	withFakeIAM(t, fake)

	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://kc.example.com/realms/demo", "myceliam-demo", "azp", "my-app", "my-app", false, false, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc trustPolicyDocument
	if err := json.Unmarshal([]byte(awssdk.ToString(fake.updateCalls[0].PolicyDocument)), &doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Statement) != 2 {
		t.Fatalf("expected 2 statements (existing + new), got %d: %+v", len(doc.Statement), doc.Statement)
	}
	foundEC2 := false
	for _, s := range doc.Statement {
		if s.Sid == "TrustEC2" {
			foundEC2 = true
		}
	}
	if !foundEC2 {
		t.Fatalf("expected pre-existing TrustEC2 statement to survive, got %+v", doc.Statement)
	}
}

func TestEnsureRoleTrustIsIdempotent(t *testing.T) {
	sid := roleTrustStatementID("https://kc.example.com/realms/demo", "azp", "my-app")
	existing := trustPolicyStatement{
		Sid:       sid,
		Effect:    "Allow",
		Principal: map[string]any{"Federated": "arn:aws:iam::111111111111:oidc-provider/kc.example.com/realms/demo"},
		Action:    []any{"sts:AssumeRoleWithWebIdentity"},
		Condition: map[string]map[string]any{
			"ForAnyValue:StringEquals": {
				"kc.example.com/realms/demo:aud": []any{"myceliam-demo", "my-app"},
			},
		},
	}
	fake := &fakeIAM{getRoleOutput: &iam.GetRoleOutput{Role: &types.Role{
		RoleName:                 awssdk.String("role-a"),
		AssumeRolePolicyDocument: trustPolicyWith(existing),
	}}}
	withFakeIAM(t, fake)

	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://kc.example.com/realms/demo", "myceliam-demo", "azp", "my-app", "my-app", false, false, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.updateCalls) != 0 {
		t.Fatalf("expected no update call when statement is already correct, got %d", len(fake.updateCalls))
	}
}

// TestEnsureRoleTrustCreatesMissingRole guards the requested behavior
// change: a role that doesn't exist yet is no longer a hard failure —
// EnsureRoleTrust creates it with the web-identity trust statement as its
// entire initial trust policy (no permissions attached, myceliam still only
// ever manages trust).
func TestEnsureRoleTrustCreatesMissingRole(t *testing.T) {
	fake := &fakeIAM{getRoleErr: noSuchEntityErr()}
	withFakeIAM(t, fake)

	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://kc.example.com/realms/demo", "myceliam-demo", "azp", "my-app", "my-app", false, false, testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.createRoleCalls) != 1 {
		t.Fatalf("expected 1 CreateRole call, got %d", len(fake.createRoleCalls))
	}
	if len(fake.updateCalls) != 0 {
		t.Fatalf("expected no UpdateAssumeRolePolicy call when creating a new role, got %d", len(fake.updateCalls))
	}
	call := fake.createRoleCalls[0]
	if awssdk.ToString(call.RoleName) != "role-a" {
		t.Fatalf("unexpected RoleName: %v", awssdk.ToString(call.RoleName))
	}
	var doc trustPolicyDocument
	if err := json.Unmarshal([]byte(awssdk.ToString(call.AssumeRolePolicyDocument)), &doc); err != nil {
		t.Fatalf("unexpected error unmarshaling policy: %v", err)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("expected exactly 1 statement in the new role's trust policy, got %d: %+v", len(doc.Statement), doc.Statement)
	}
	aud, _ := doc.Statement[0].Condition["ForAnyValue:StringEquals"]["kc.example.com/realms/demo:aud"].([]any)
	if len(aud) != 2 || aud[0] != "myceliam-demo" || aud[1] != "my-app" {
		t.Fatalf("unexpected condition on newly-created role: %+v", doc.Statement[0].Condition)
	}
	// Confirmed live: AWS's CreateRole "description" field only accepts
	// tab/LF/CR plus printable ASCII (0x20-0x7E) and the Latin-1 supplement
	// (0xA1-0xFF) — an em dash or smart quote 400s with ValidationError
	// regardless of how correct the trust policy itself is.
	if desc := awssdk.ToString(call.Description); !awsDescriptionCharsetRe.MatchString(desc) {
		t.Fatalf("Description contains characters AWS's CreateRole rejects: %q", desc)
	}
}

var awsDescriptionCharsetRe = regexp.MustCompile("^[\t\n\r -~¡-ÿ]*$")


// TestEnsureRoleTrustPropagatesCreateRoleError guards the other branch: a
// real CreateRole failure (as opposed to NoSuchEntity from GetRole) must
// still surface as an error, not be silently swallowed.
func TestEnsureRoleTrustPropagatesCreateRoleError(t *testing.T) {
	fake := &fakeIAM{getRoleErr: noSuchEntityErr(), createRoleErr: errors.New("boom")}
	withFakeIAM(t, fake)

	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://kc.example.com/realms/demo", "myceliam-demo", "azp", "my-app", "my-app", false, false, testCreds())
	if err == nil {
		t.Fatal("expected an error when CreateRole fails")
	}
}

func TestRemoveRoleTrustLeavesOtherStatements(t *testing.T) {
	sid := roleTrustStatementID("https://kc.example.com/realms/demo", "azp", "my-app")
	ours := trustPolicyStatement{Sid: sid, Effect: "Allow", Principal: map[string]any{"Federated": "x"}, Action: "sts:AssumeRoleWithWebIdentity"}
	other := trustPolicyStatement{Sid: "TrustEC2", Effect: "Allow", Principal: map[string]any{"Service": "ec2.amazonaws.com"}, Action: "sts:AssumeRole"}
	fake := &fakeIAM{getRoleOutput: &iam.GetRoleOutput{Role: &types.Role{
		RoleName:                 awssdk.String("role-a"),
		AssumeRolePolicyDocument: trustPolicyWith(ours, other),
	}}}
	withFakeIAM(t, fake)

	err := RemoveRoleTrust(context.Background(), "111111111111", "role-a", "https://kc.example.com/realms/demo", "azp", "my-app", testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc trustPolicyDocument
	if err := json.Unmarshal([]byte(awssdk.ToString(fake.updateCalls[0].PolicyDocument)), &doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Statement) != 1 || doc.Statement[0].Sid != "TrustEC2" {
		t.Fatalf("expected only TrustEC2 to remain, got %+v", doc.Statement)
	}
}

func TestRemoveRoleTrustNoopWhenAbsent(t *testing.T) {
	fake := &fakeIAM{getRoleOutput: &iam.GetRoleOutput{Role: &types.Role{
		RoleName:                 awssdk.String("role-a"),
		AssumeRolePolicyDocument: trustPolicyWith(),
	}}}
	withFakeIAM(t, fake)

	if err := RemoveRoleTrust(context.Background(), "111111111111", "role-a", "https://kc.example.com/realms/demo", "azp", "my-app", testCreds()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.updateCalls) != 0 {
		t.Fatalf("expected no update call, got %d", len(fake.updateCalls))
	}
}

func TestRemoveRoleTrustNoopWhenRoleGone(t *testing.T) {
	fake := &fakeIAM{getRoleErr: noSuchEntityErr()}
	withFakeIAM(t, fake)

	if err := RemoveRoleTrust(context.Background(), "111111111111", "role-a", "https://kc.example.com/realms/demo", "azp", "my-app", testCreds()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

var _ smithy.APIError = (*types.NoSuchEntityException)(nil) // sanity: confirms our fake error satisfies the same interface isNoSuchEntity checks against
