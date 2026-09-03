// Package v1 defines the Go types for myceliam.io/v1's CRDs: AwsAccessProfile,
// GcpAccessProfile, and AutoidpAllowlist.
//
// Hand-written rather than controller-gen-generated: these CRDs are small and
// their schema puts fields directly on the object rather than nested under
// .spec/.status — controller-gen assumes the spec/status convention, so
// generating from Go type markers would mean fighting the tool to reproduce a
// shape it doesn't expect. Hand-writing the equivalent DeepCopy methods is the
// same amount of code either way.
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	GroupName              = "myceliam.io"
	GroupVersion           = "v1"
	AwsProfilePlural       = "awsaccessprofiles"
	GcpProfilePlural       = "gcpaccessprofiles"
	AutoidpAllowlistPlural = "autoidpallowlists"

	// AutoidpAllowlistNamespace/Name are the fixed, singleton location every
	// reconciler looks up — there is exactly one AutoidpAllowlist per cluster.
	// Living in myceliam-system means restricting who can write it is a plain
	// namespaced Role/RoleBinding, not a bespoke cluster-scoped-resource RBAC
	// setup.
	AutoidpAllowlistNamespace = "myceliam-system"
	AutoidpAllowlistName      = "default"
)

// SchemeGroupVersion is group version used to register these types.
var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: GroupVersion}

// SchemeBuilder/AddToScheme register these types (and their List types) with
// a controller-runtime/client-go runtime.Scheme.
var (
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&AwsAccessProfile{}, &AwsAccessProfileList{},
		&GcpAccessProfile{}, &GcpAccessProfileList{},
		&AutoidpAllowlist{}, &AutoidpAllowlistList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// AwsAccessProfile mirrors deploy/crds/awsaccessprofile.yaml: `accounts` maps
// each AWS account ID to the list of IAM role *names* in that account. Any
// ServiceAccount that opts in via the myceliam.io/aws-access-profile label
// gets trust-policy access added on *every* role listed for *every* account
// here — there is no per-SA role selection; SAs needing a different, narrower,
// or wider set of roles should reference a different AwsAccessProfile.
// myceliam never creates these roles — they're provisioned out-of-band by the
// account owner, exactly like the existing bootstrap myceliam-operator role —
// it only manages each named role's trust policy to add/remove the requesting
// entity's condition.
type AwsAccessProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Accounts map[string][]string `json:"accounts"`
}

// AwsAccessProfileList is a list of AwsAccessProfile.
type AwsAccessProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AwsAccessProfile `json:"items"`
}

// GcpAccessProfile mirrors deploy/crds/gcpaccessprofile.yaml: `projects` maps
// each GCP project ID to the list of GCP service account *emails* in that
// project. Any ServiceAccount that opts in via the myceliam.io/gcp-access-
// profile label gets impersonation access granted on *every* email listed
// for *every* project here — same all-or-nothing-per-profile model as
// AwsAccessProfile above. myceliam never creates these service accounts —
// provisioned out-of-band — it only grants/revokes
// roles/iam.workloadIdentityUser on the named target SA for the requesting
// entity's WLI principal.
type GcpAccessProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Projects map[string][]string `json:"projects"`
}

// GcpAccessProfileList is a list of GcpAccessProfile.
type GcpAccessProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []GcpAccessProfile `json:"items"`
}

// AutoidpAllowlist gates which namespaces' ServiceAccounts myceliam will
// actually provision identities for. A single instance is expected, at
// AutoidpAllowlistNamespace/AutoidpAllowlistName.
//
// Absent entirely: every namespace is allowed (today's behavior, preserved
// for zero-config backward compatibility). Present: only namespaces listed in
// Namespaces are provisioned — anything else's autoidp=true ServiceAccounts
// sit unreconciled with a logged Forbidden error, until either the namespace
// is added here or the label is removed. Security boundary is deliberately
// plain Kubernetes RBAC on this one object (who can write to myceliam-system),
// not anything myceliam itself enforces beyond reading it.
//
// Only ever gates *provisioning* (ensure paths) — never blocks cleanup/delete,
// so removing a namespace from this list is not itself destructive to
// whatever was already provisioned for it.
type AutoidpAllowlist struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Flat list for now — regex/include-exclude rules are a deliberately
	// deferred future extension, not needed for the initial cut.
	Namespaces []string `json:"namespaces"`
}

// AutoidpAllowlistList is a list of AutoidpAllowlist.
type AutoidpAllowlistList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AutoidpAllowlist `json:"items"`
}
