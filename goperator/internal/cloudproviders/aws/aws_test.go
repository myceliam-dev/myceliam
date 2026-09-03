package aws

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"

	"myceliam/internal/operr"
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

	err := DeleteIdp(context.Background(), "111111111111", "https://kc.example.com/realms/demo", testCreds())
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

	if err := DeleteIdp(context.Background(), "111111111111", "https://kc.example.com/realms/demo", testCreds()); err != nil {
		t.Fatalf("unexpected error: %v", err)
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

	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://kc.example.com/realms/demo", "myceliam-demo", "azp", "my-app", testCreds())
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
	if stmt.Effect != "Allow" || stmt.Action != "sts:AssumeRoleWithWebIdentity" {
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

func TestEnsureRoleTrustSpiffePathChecksAudAndSub(t *testing.T) {
	fake := &fakeIAM{getRoleOutput: &iam.GetRoleOutput{Role: &types.Role{
		RoleName:                 awssdk.String("role-a"),
		AssumeRolePolicyDocument: trustPolicyWith(),
	}}}
	withFakeIAM(t, fake)

	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://spire.example.com", "myceliam-demo", "sub", "spiffe://example.org/ns/demo/sa/my-app", testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc trustPolicyDocument
	if err := json.Unmarshal([]byte(awssdk.ToString(fake.updateCalls[0].PolicyDocument)), &doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cond := doc.Statement[0].Condition["StringEquals"]
	if cond["spire.example.com:aud"] != "myceliam-demo" || cond["spire.example.com:sub"] != "spiffe://example.org/ns/demo/sa/my-app" {
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

	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://kc.example.com/realms/demo", "myceliam-demo", "azp", "my-app", testCreds())
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
		Action:    "sts:AssumeRoleWithWebIdentity",
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

	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://kc.example.com/realms/demo", "myceliam-demo", "azp", "my-app", testCreds())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.updateCalls) != 0 {
		t.Fatalf("expected no update call when statement is already correct, got %d", len(fake.updateCalls))
	}
}

func TestEnsureRoleTrustRejectsMissingRole(t *testing.T) {
	fake := &fakeIAM{getRoleErr: noSuchEntityErr()}
	withFakeIAM(t, fake)

	err := EnsureRoleTrust(context.Background(), "111111111111", "role-a", "https://kc.example.com/realms/demo", "myceliam-demo", "azp", "my-app", testCreds())
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
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
