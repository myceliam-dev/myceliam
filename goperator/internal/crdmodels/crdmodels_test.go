package crdmodels

import (
	"reflect"
	"testing"

	"myceliam/internal/operr"
)

func TestParseAwsAccessProfile(t *testing.T) {
	body := map[string]any{
		"metadata": map[string]any{"namespace": "default", "name": "ap1"},
		"accounts": []any{"app-dev", "app-qa", "app-stg", "app-prod"},
	}
	profile, err := ParseAwsAccessProfile(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile.Name != "ap1" || profile.Namespace != "default" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	want := []string{"app-dev", "app-qa", "app-stg", "app-prod"}
	if !reflect.DeepEqual(profile.Accounts, want) {
		t.Fatalf("unexpected accounts: %v", profile.Accounts)
	}
}

func TestParseGcpAccessProfile(t *testing.T) {
	body := map[string]any{
		"metadata": map[string]any{"namespace": "default", "name": "ap2"},
		"projects": []any{"dataplane-dev", "dataplane-qa", "dataplane-stg", "dataplane-prod"},
	}
	profile, err := ParseGcpAccessProfile(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile.Name != "ap2" || profile.Namespace != "default" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	want := []string{"dataplane-dev", "dataplane-qa", "dataplane-stg", "dataplane-prod"}
	if !reflect.DeepEqual(profile.Projects, want) {
		t.Fatalf("unexpected projects: %v", profile.Projects)
	}
}

func TestAwsProfileRequiresAccounts(t *testing.T) {
	body := map[string]any{
		"metadata": map[string]any{"namespace": "default", "name": "ap1"},
		"accounts": []any{},
	}
	_, err := ParseAwsAccessProfile(body)
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}

func TestGcpProfileRequiresProjects(t *testing.T) {
	body := map[string]any{
		"metadata": map[string]any{"namespace": "default", "name": "ap2"},
	}
	_, err := ParseGcpAccessProfile(body)
	if _, ok := operr.AsPermanent(err); !ok {
		t.Fatalf("expected *operr.Permanent, got %v", err)
	}
}
