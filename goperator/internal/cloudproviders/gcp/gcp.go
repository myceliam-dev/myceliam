// Package gcp ports pythonoperator/src/myceliam/cloud_providers/gcp.py: GCP
// IdP federation (myceliam.io/gcp-access-profile label). Registers each
// namespace's OIDC-compatible identity source as a provider inside a single
// shared Workload Identity Pool (Settings.GcpWorkloadIdentityPoolID), one such
// pool per GCP project listed across GcpAccessProfile CRs.
//
// Registration only — this does not create the GCP IAM binding that would
// actually grant permissions once federated; that's left to project owners.
//
// Within that pool, a namespace gets one provider *per KIND* — not one
// provider overall — because two different client types can coexist in the
// same namespace but point at genuinely different issuers with different
// token conventions (a Keycloak realm vs. a SPIRE OIDC Discovery Provider).
// Sharing one provider between them would mean whichever kind reconciles last
// silently overwrites the other's issuer/audience/attributeMapping.
// KindOIDC covers clienttype=secret/signedjwt; KindSpiffe covers
// clienttype=spiffe. Each kind carries its own fixed convention in
// kindConfigs below — whether to embed JWKS directly vs. rely on GCP's live
// discovery, and which claim google.subject maps from.
//
// Pool existence is ensured directly off GcpAccessProfile reconciliation
// (EnsurePool, once per project listed); providers are ensured off SA-label
// reconciliation (EnsureIdp, once per namespace/kind/project triple).
//
// Uses raw REST calls rather than a GCP SDK, to avoid pulling in Application
// Default Credentials machinery — the operator's own GCP access token (from
// operatoridentity.GetGCPAccessToken) is used directly as a bearer token.
package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"myceliam/internal/config"
	"myceliam/internal/httpx"
	"myceliam/internal/oidc"
	"myceliam/internal/operatoridentity"
	"myceliam/internal/operr"
)

const (
	KindOIDC   = "oidc"
	KindSpiffe = "spiffe"

	idpCallDelay = 30 * time.Second
)

// iamAPIBase, cloudResourceManagerAPIBase, and httpClient are package-level
// vars so tests can point them at an httptest.Server instead of Google's real
// endpoints.
var (
	iamAPIBase                  = "https://iam.googleapis.com/v1"
	cloudResourceManagerAPIBase = "https://cloudresourcemanager.googleapis.com/v1"
	httpClient                  = &http.Client{Timeout: 30 * time.Second}
)

const workloadIdentityUserRole = "roles/iam.workloadIdentityUser"

// getGCPAccessToken is a package-level seam over operatoridentity.GetGCPAccessToken
// so tests can stub it without a live token exchange — the Go equivalent of
// the Python suite's mocker.patch("...gcp.get_gcp_access_token").
var getGCPAccessToken = operatoridentity.GetGCPAccessToken

type kindConfig struct {
	embedJWKS    bool
	subjectClaim string
}

// kindConfigs holds the per-kind token conventions — see package doc.
// embedJWKS: whether to fetch and embed the issuer's JWKS directly rather
// than rely on GCP's live discovery. subjectClaim: which token claim
// google.subject is mapped from ("azp" for Keycloak-issued tokens, which
// always set azp to the client_id; SPIFFE JWT-SVIDs never carry azp at all,
// so KindSpiffe maps from "sub" — the claim holding the SPIFFE ID itself).
var kindConfigs = map[string]kindConfig{
	KindOIDC:   {embedJWKS: true, subjectClaim: "azp"},
	KindSpiffe: {embedJWKS: false, subjectClaim: "sub"},
}

// providerID mirrors gcp.py's _provider_id, extended with ClusterID in place
// of a fixed "myceliam" prefix — two clusters sharing this GCP project must
// never collide on the same provider ID just because they happen to have a
// namespace with the same name (see config.Settings.ClusterID's own doc
// comment). WLI provider IDs must be 4-32 chars of lowercase letters/digits/
// hyphens. Room for the "-<kind>" suffix is reserved before truncating the
// cluster+namespace-derived base, so oidc/spiffe providers for the same
// (long) cluster/namespace never collide on one truncated ID.
func providerID(namespace, kind string, settings *config.Settings) string {
	suffix := "-" + kind
	base := settings.ClusterID + "-" + namespace
	if maxBaseLen := 32 - len(suffix); len(base) > maxBaseLen {
		base = base[:maxBaseLen]
	}
	base = strings.TrimRight(base, "-")
	return base + suffix
}

type apiResponse struct {
	StatusCode int
	Body       []byte
}

func (r *apiResponse) decode(v any) error {
	return json.Unmarshal(r.Body, v)
}

func doRequest(ctx context.Context, method, url, accessToken string, query map[string]string, jsonBody any) (*apiResponse, error) {
	var bodyReader io.Reader
	if jsonBody != nil {
		b, err := json.Marshal(jsonBody)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(b)
	}
	if len(query) > 0 {
		var parts []string
		for k, v := range query {
			parts = append(parts, k+"="+v)
		}
		url += "?" + strings.Join(parts, "&")
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	if jsonBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &apiResponse{StatusCode: resp.StatusCode, Body: body}, nil
}

func raiseForStatus(resp *apiResponse, action string) error {
	if resp.StatusCode >= 400 {
		return operr.Temporaryf(idpCallDelay, "Error %s: %d %s", action, resp.StatusCode, string(resp.Body))
	}
	return nil
}

func fetchJWKS(ctx context.Context, issuerURL string, settings *config.Settings) (string, error) {
	client := httpx.NewClient(settings.KeycloakVerifySSL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(issuerURL, "/")+"/protocol/openid-connect/certs", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", operr.Temporaryf(idpCallDelay, "Error fetching JWKS from %s: %v", issuerURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", operr.Temporaryf(idpCallDelay, "Error fetching JWKS from %s: %d %s", issuerURL, resp.StatusCode, string(body))
	}
	return string(body), nil
}

// undelete requests GCP to undelete a soft-deleted WLI pool/provider. This is
// an async long-running operation — it returns before the resource is
// actually restored, so callers must not chain another call directly onto it
// and should force a retry instead (see EnsurePool/EnsureIdp).
func undelete(ctx context.Context, accessToken, resourceName, action string) error {
	resp, err := doRequest(ctx, http.MethodPost, fmt.Sprintf("%s/%s:undelete", iamAPIBase, resourceName), accessToken, nil, nil)
	if err != nil {
		return operr.Temporaryf(idpCallDelay, "Error %s: %v", action, err)
	}
	return raiseForStatus(resp, action)
}

// EnsurePool ensures the shared Workload Identity Pool
// (Settings.GcpWorkloadIdentityPoolID) exists in the given project. Called
// once per project listed on a GcpAccessProfile, independent of any specific
// namespace/SA.
func EnsurePool(ctx context.Context, projectID string, settings *config.Settings, oidcProvider oidc.Provider) error {
	accessToken, err := getGCPAccessToken(ctx, settings, oidcProvider)
	if err != nil {
		return err
	}
	poolID := settings.GcpWorkloadIdentityPoolID
	poolName := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s", projectID, poolID)

	poolResp, err := doRequest(ctx, http.MethodGet, iamAPIBase+"/"+poolName, accessToken, nil, nil)
	if err != nil {
		return operr.Temporaryf(idpCallDelay, "Error checking WLI pool %s: %v", poolName, err)
	}

	switch {
	case poolResp.StatusCode == 404:
		createResp, err := doRequest(
			ctx, http.MethodPost,
			fmt.Sprintf("%s/projects/%s/locations/global/workloadIdentityPools", iamAPIBase, projectID),
			accessToken,
			map[string]string{"workloadIdentityPoolId": poolID},
			map[string]any{"displayName": poolID, "state": "ACTIVE"},
		)
		if err != nil {
			return operr.Temporaryf(idpCallDelay, "Error creating WLI pool %s: %v", poolName, err)
		}
		return raiseForStatus(createResp, "creating WLI pool "+poolName)

	case poolResp.StatusCode < 400:
		var parsed struct {
			State string `json:"state"`
		}
		if err := poolResp.decode(&parsed); err != nil {
			return fmt.Errorf("decoding WLI pool %s response: %w", poolName, err)
		}
		if parsed.State == "DELETED" {
			if err := undelete(ctx, accessToken, poolName, "undeleting WLI pool "+poolName); err != nil {
				return err
			}
			return operr.Temporaryf(15*time.Second, "WLI pool %s was DELETED; undelete requested", poolName)
		}
		return nil

	default:
		return raiseForStatus(poolResp, "checking WLI pool "+poolName)
	}
}

// EnsureIdp ensures the KindOIDC/KindSpiffe provider for this namespace's
// issuer exists inside the shared Workload Identity Pool
// (Settings.GcpWorkloadIdentityPoolID) in the given project. Assumes the pool
// itself already exists — that's EnsurePool's job, triggered separately off
// GcpAccessProfile reconciliation. kind picks which per-kind convention from
// kindConfigs (JWKS embedding, subject-claim mapping) applies — see package doc.
func EnsureIdp(ctx context.Context, projectID, namespace, issuerURL, audience string, settings *config.Settings, kind string, oidcProvider oidc.Provider) error {
	kc := kindConfigs[kind]
	accessToken, err := getGCPAccessToken(ctx, settings, oidcProvider)
	if err != nil {
		return err
	}
	poolName := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s", projectID, settings.GcpWorkloadIdentityPoolID)
	pid := providerID(namespace, kind, settings)
	providerName := fmt.Sprintf("%s/providers/%s", poolName, pid)

	oidcPayload := map[string]any{
		"issuerUri":        issuerURL,
		"allowedAudiences": []string{audience},
	}
	if kc.embedJWKS {
		jwksJSON, err := fetchJWKS(ctx, issuerURL, settings)
		if err != nil {
			return err
		}
		oidcPayload["jwksJson"] = jwksJSON
	}
	providerPayload := map[string]any{
		"displayName": pid,
		"state":       "ACTIVE",
		"oidc":        oidcPayload,
		"attributeMapping": map[string]string{
			"google.subject": "assertion." + kc.subjectClaim,
		},
	}

	providerResp, err := doRequest(ctx, http.MethodGet, iamAPIBase+"/"+providerName, accessToken, nil, nil)
	if err != nil {
		return operr.Temporaryf(idpCallDelay, "Error checking WLI provider %s: %v", providerName, err)
	}

	switch {
	case providerResp.StatusCode == 404:
		createResp, err := doRequest(
			ctx, http.MethodPost, fmt.Sprintf("%s/%s/providers", iamAPIBase, poolName), accessToken,
			map[string]string{"workloadIdentityPoolProviderId": pid}, providerPayload,
		)
		if err != nil {
			return operr.Temporaryf(idpCallDelay, "Error creating WLI provider %s: %v", providerName, err)
		}
		return raiseForStatus(createResp, "creating WLI provider "+providerName)

	case providerResp.StatusCode >= 400:
		return raiseForStatus(providerResp, "checking WLI provider "+providerName)

	default:
		var parsed struct {
			State string `json:"state"`
		}
		if err := providerResp.decode(&parsed); err != nil {
			return fmt.Errorf("decoding WLI provider %s response: %w", providerName, err)
		}
		if parsed.State == "DELETED" {
			if err := undelete(ctx, accessToken, providerName, "undeleting WLI provider "+providerName); err != nil {
				return err
			}
			return operr.Temporaryf(15*time.Second, "WLI provider %s was DELETED; undelete requested", providerName)
		}
		updateResp, err := doRequest(
			ctx, http.MethodPatch, iamAPIBase+"/"+providerName, accessToken,
			map[string]string{"updateMask": "oidc,attributeMapping"}, providerPayload,
		)
		if err != nil {
			return operr.Temporaryf(idpCallDelay, "Error updating WLI provider %s: %v", providerName, err)
		}
		return raiseForStatus(updateResp, "updating WLI provider "+providerName)
	}
}

// DeleteIdp deletes the KindOIDC/KindSpiffe provider for this namespace, if
// present. No-op on 404.
func DeleteIdp(ctx context.Context, projectID, namespace string, settings *config.Settings, kind string, oidcProvider oidc.Provider) error {
	accessToken, err := getGCPAccessToken(ctx, settings, oidcProvider)
	if err != nil {
		return err
	}
	pid := providerID(namespace, kind, settings)
	providerName := fmt.Sprintf(
		"projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		projectID, settings.GcpWorkloadIdentityPoolID, pid,
	)

	resp, err := doRequest(ctx, http.MethodDelete, iamAPIBase+"/"+providerName, accessToken, nil, nil)
	if err != nil {
		return operr.Temporaryf(idpCallDelay, "Error deleting WLI provider %s: %v", providerName, err)
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return raiseForStatus(resp, "deleting WLI provider "+providerName)
}

// iamPolicy/iamBinding are a minimal model of a GCP resource IAM policy —
// just enough structure to find-and-modify the workloadIdentityUser
// binding's members list without disturbing any other role binding already
// on the target service account.
type iamPolicy struct {
	Bindings []iamBinding `json:"bindings"`
	Etag     string       `json:"etag,omitempty"`
	Version  int          `json:"version,omitempty"`
}

type iamBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

func addMember(policy *iamPolicy, role, member string) bool {
	for i := range policy.Bindings {
		if policy.Bindings[i].Role != role {
			continue
		}
		for _, m := range policy.Bindings[i].Members {
			if m == member {
				return false
			}
		}
		policy.Bindings[i].Members = append(policy.Bindings[i].Members, member)
		return true
	}
	policy.Bindings = append(policy.Bindings, iamBinding{Role: role, Members: []string{member}})
	return true
}

func removeMember(policy *iamPolicy, role, member string) bool {
	for i := range policy.Bindings {
		if policy.Bindings[i].Role != role {
			continue
		}
		kept := make([]string, 0, len(policy.Bindings[i].Members))
		removed := false
		for _, m := range policy.Bindings[i].Members {
			if m == member {
				removed = true
				continue
			}
			kept = append(kept, m)
		}
		policy.Bindings[i].Members = kept
		return removed
	}
	return false
}

// resolveProjectNumber looks up poolProjectID's numeric project number — GCP
// principal identifier strings (used below) require the project *number*,
// not the project ID string used everywhere else in this package's resource
// paths (GCP resource paths accept either; principal identifiers require the
// number specifically).
func resolveProjectNumber(ctx context.Context, accessToken, projectID string) (string, error) {
	resp, err := doRequest(ctx, http.MethodGet, cloudResourceManagerAPIBase+"/projects/"+projectID, accessToken, nil, nil)
	if err != nil {
		return "", operr.Temporaryf(idpCallDelay, "Error resolving GCP project number for %s: %v", projectID, err)
	}
	if err := raiseForStatus(resp, "resolving project number for "+projectID); err != nil {
		return "", err
	}
	var parsed struct {
		ProjectNumber string `json:"projectNumber"`
	}
	if err := resp.decode(&parsed); err != nil {
		return "", fmt.Errorf("decoding project number response for %s: %w", projectID, err)
	}
	return parsed.ProjectNumber, nil
}

func workloadIdentityPrincipal(projectNumber, poolID, subjectValue string) string {
	return fmt.Sprintf(
		"principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/subject/%s",
		projectNumber, poolID, subjectValue,
	)
}

// GrantImpersonation grants roles/iam.workloadIdentityUser on targetSAEmail
// to the WLI principal identified by (poolProjectID's pool, subjectValue) —
// i.e. the specific entity behind this namespace's WLI provider (the SA name
// for Keycloak-issued tokens, or the SPIFFE ID for SPIFFE-issued ones — see
// models.SpiffeIDAnnotation). targetSAEmail's own project can differ from
// poolProjectID; GCP resolves it from the email itself.
//
// targetSAEmail must already exist — myceliam never creates GCP service
// accounts, only grants impersonation on ones project owners provisioned
// out-of-band (same registration-only model as the WLI provider itself).
func GrantImpersonation(ctx context.Context, targetSAEmail, poolProjectID, subjectValue string, settings *config.Settings, oidcProvider oidc.Provider) error {
	accessToken, err := getGCPAccessToken(ctx, settings, oidcProvider)
	if err != nil {
		return err
	}
	projectNumber, err := resolveProjectNumber(ctx, accessToken, poolProjectID)
	if err != nil {
		return err
	}
	member := workloadIdentityPrincipal(projectNumber, settings.GcpWorkloadIdentityPoolID, subjectValue)

	policyURL := fmt.Sprintf("%s/projects/-/serviceAccounts/%s:getIamPolicy", iamAPIBase, targetSAEmail)
	getResp, err := doRequest(ctx, http.MethodPost, policyURL, accessToken, nil, map[string]any{})
	if err != nil {
		return operr.Temporaryf(idpCallDelay, "Error reading IAM policy for %s: %v", targetSAEmail, err)
	}
	if getResp.StatusCode == http.StatusNotFound {
		return operr.Permanentf(
			"GCP service account '%s' does not exist (or the operator's own "+
				"credential lacks visibility on it — GCP returns 404 rather than "+
				"403 in that case) — response body: %s", targetSAEmail, strings.TrimSpace(string(getResp.Body)),
		)
	}
	if err := raiseForStatus(getResp, "reading IAM policy for "+targetSAEmail); err != nil {
		return err
	}

	var policy iamPolicy
	if err := getResp.decode(&policy); err != nil {
		return fmt.Errorf("decoding IAM policy for %s: %w", targetSAEmail, err)
	}

	if !addMember(&policy, workloadIdentityUserRole, member) {
		return nil
	}

	setURL := fmt.Sprintf("%s/projects/-/serviceAccounts/%s:setIamPolicy", iamAPIBase, targetSAEmail)
	setResp, err := doRequest(ctx, http.MethodPost, setURL, accessToken, nil, map[string]any{"policy": policy})
	if err != nil {
		return operr.Temporaryf(idpCallDelay, "Error updating IAM policy for %s: %v", targetSAEmail, err)
	}
	return raiseForStatus(setResp, "updating IAM policy for "+targetSAEmail)
}

// RevokeImpersonation removes the impersonation grant GrantImpersonation
// added for this entity, leaving every other binding on targetSAEmail's IAM
// policy untouched. No-op if the service account or the grant is already gone.
func RevokeImpersonation(ctx context.Context, targetSAEmail, poolProjectID, subjectValue string, settings *config.Settings, oidcProvider oidc.Provider) error {
	accessToken, err := getGCPAccessToken(ctx, settings, oidcProvider)
	if err != nil {
		return err
	}
	projectNumber, err := resolveProjectNumber(ctx, accessToken, poolProjectID)
	if err != nil {
		return err
	}
	member := workloadIdentityPrincipal(projectNumber, settings.GcpWorkloadIdentityPoolID, subjectValue)

	policyURL := fmt.Sprintf("%s/projects/-/serviceAccounts/%s:getIamPolicy", iamAPIBase, targetSAEmail)
	getResp, err := doRequest(ctx, http.MethodPost, policyURL, accessToken, nil, map[string]any{})
	if err != nil {
		return operr.Temporaryf(idpCallDelay, "Error reading IAM policy for %s: %v", targetSAEmail, err)
	}
	if getResp.StatusCode == http.StatusNotFound {
		return nil
	}
	if err := raiseForStatus(getResp, "reading IAM policy for "+targetSAEmail); err != nil {
		return err
	}

	var policy iamPolicy
	if err := getResp.decode(&policy); err != nil {
		return fmt.Errorf("decoding IAM policy for %s: %w", targetSAEmail, err)
	}

	if !removeMember(&policy, workloadIdentityUserRole, member) {
		return nil
	}

	setURL := fmt.Sprintf("%s/projects/-/serviceAccounts/%s:setIamPolicy", iamAPIBase, targetSAEmail)
	setResp, err := doRequest(ctx, http.MethodPost, setURL, accessToken, nil, map[string]any{"policy": policy})
	if err != nil {
		return operr.Temporaryf(idpCallDelay, "Error updating IAM policy for %s: %v", targetSAEmail, err)
	}
	return raiseForStatus(setResp, "updating IAM policy for "+targetSAEmail)
}
