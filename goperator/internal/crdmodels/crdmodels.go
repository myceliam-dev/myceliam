// Package crdmodels ports pythonoperator/src/myceliam/crd_models.py: parsing
// the AwsAccessProfile/GcpAccessProfile custom resources out of their raw
// unstructured body (map[string]interface{}, the same shape
// k8s.io/apimachinery/pkg/apis/meta/v1/unstructured.Unstructured.Object has).
package crdmodels

import (
	"myceliam/internal/operr"
)

const (
	AwsProfilePlural = "awsaccessprofiles"
	GcpProfilePlural = "gcpaccessprofiles"
)

type AwsAccessProfile struct {
	Name      string
	Namespace string
	Accounts  []string
}

type GcpAccessProfile struct {
	Name      string
	Namespace string
	Projects  []string
}

func metadataStrings(body map[string]any) (namespace, name string) {
	meta, _ := body["metadata"].(map[string]any)
	namespace, _ = meta["namespace"].(string)
	name, _ = meta["name"].(string)
	return namespace, name
}

func stringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ParseAwsAccessProfile mirrors crd_models.py's parse_aws_access_profile.
// Returns an *operr.Permanent if body has no accounts listed.
func ParseAwsAccessProfile(body map[string]any) (*AwsAccessProfile, error) {
	namespace, name := metadataStrings(body)
	accounts := stringSlice(body["accounts"])
	if len(accounts) == 0 {
		return nil, operr.Permanentf("AwsAccessProfile '%s/%s' has no accounts listed", namespace, name)
	}
	return &AwsAccessProfile{Name: name, Namespace: namespace, Accounts: accounts}, nil
}

// ParseGcpAccessProfile mirrors crd_models.py's parse_gcp_access_profile.
// Returns an *operr.Permanent if body has no projects listed.
func ParseGcpAccessProfile(body map[string]any) (*GcpAccessProfile, error) {
	namespace, name := metadataStrings(body)
	projects := stringSlice(body["projects"])
	if len(projects) == 0 {
		return nil, operr.Permanentf("GcpAccessProfile '%s/%s' has no projects listed", namespace, name)
	}
	return &GcpAccessProfile{Name: name, Namespace: namespace, Projects: projects}, nil
}
