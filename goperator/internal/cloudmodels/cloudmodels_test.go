package cloudmodels

import (
	"testing"

	"myceliam/internal/config"
	"myceliam/internal/models"
)

func settings(t *testing.T, overrides map[string]string) *config.Settings {
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

func TestNoLabelsYieldsNoSpecs(t *testing.T) {
	specs, err := ParseCloudFederationSpecs("ns1", "my-app", map[string]string{}, map[string]string{}, settings(t, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(specs) != 0 {
		t.Fatalf("expected no specs, got %v", specs)
	}
}

func TestAwsOnly(t *testing.T) {
	labels := map[string]string{AwsProfileLabel: "ap1"}
	specs, err := ParseCloudFederationSpecs("ns1", "my-app", labels, map[string]string{}, settings(t, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %v", specs)
	}
	spec := specs[0]
	// aws's scope name and audience are both "aws-<namespace>-<sa>" —
	// unique per SA, independent of profile name — see
	// ParseCloudFederationSpecs's own doc comment.
	if spec.Cloud != "aws" || spec.ProfileName != "ap1" || spec.ScopeName != "aws-ns1-my-app" || spec.Audience != "aws-ns1-my-app" {
		t.Fatalf("unexpected spec: %+v", spec)
	}
}

func TestGcpOnly(t *testing.T) {
	labels := map[string]string{GcpProfileLabel: "ap2"}
	specs, err := ParseCloudFederationSpecs("ns1", "my-app", labels, map[string]string{}, settings(t, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %v", specs)
	}
	spec := specs[0]
	// gcp's scope name is per-SA ("gcp-<namespace>-<sa>") since a Keycloak
	// scope is a distinct object per SA, but its audience stays
	// namespace-shared, not per-SA — see ParseCloudFederationSpecs's own doc
	// comment for why.
	if spec.Cloud != "gcp" || spec.ProfileName != "ap2" || spec.ScopeName != "gcp-ns1-my-app" || spec.Audience != "gcp-ns1" {
		t.Fatalf("unexpected spec: %+v", spec)
	}
}

func TestBothAwsAndGcp(t *testing.T) {
	labels := map[string]string{
		AwsProfileLabel: "ap1",
		GcpProfileLabel: "ap2",
	}
	specs, err := ParseCloudFederationSpecs("ns1", "my-app", labels, map[string]string{}, settings(t, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %v", specs)
	}
	clouds := map[string]bool{}
	for _, s := range specs {
		clouds[s.Cloud] = true
		switch s.Cloud {
		case "aws":
			if s.Audience != "aws-ns1-my-app" {
				t.Fatalf("unexpected aws audience: %v", s.Audience)
			}
		case "gcp":
			if s.Audience != "gcp-ns1" {
				t.Fatalf("unexpected gcp audience: %v", s.Audience)
			}
		}
	}
	if !clouds["aws"] || !clouds["gcp"] {
		t.Fatalf("expected both aws and gcp, got %v", clouds)
	}
}

func TestIgnoresUnrelatedLabels(t *testing.T) {
	labels := map[string]string{
		models.AutoidpLabel:    "true",
		models.ClientTypeLabel: "secret",
	}
	specs, err := ParseCloudFederationSpecs("ns1", "my-app", labels, map[string]string{}, settings(t, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(specs) != 0 {
		t.Fatalf("expected no specs, got %v", specs)
	}
}

func TestAwsAudienceIsUniquePerServiceAccount(t *testing.T) {
	labels := map[string]string{AwsProfileLabel: "ap1"}
	specsA, err := ParseCloudFederationSpecs("ns1", "sa-a", labels, map[string]string{}, settings(t, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	specsB, err := ParseCloudFederationSpecs("ns1", "sa-b", labels, map[string]string{}, settings(t, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if specsA[0].Audience == specsB[0].Audience {
		t.Fatalf("expected different SAs on the same profile to get different aws audiences, both got %v", specsA[0].Audience)
	}
}

func TestGcpAudienceIsSharedAcrossServiceAccountsInANamespace(t *testing.T) {
	labels := map[string]string{GcpProfileLabel: "ap1"}
	specsA, err := ParseCloudFederationSpecs("ns1", "sa-a", labels, map[string]string{}, settings(t, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	specsB, err := ParseCloudFederationSpecs("ns1", "sa-b", labels, map[string]string{}, settings(t, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if specsA[0].Audience != specsB[0].Audience {
		t.Fatalf("expected different SAs in the same namespace to share the gcp audience, got %v and %v", specsA[0].Audience, specsB[0].Audience)
	}
}
