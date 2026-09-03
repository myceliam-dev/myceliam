// Package httpx provides the one shared bit of plumbing every raw-REST caller
// in this codebase needs: an *http.Client honoring MYCELIAM_KEYCLOAK_VERIFY_SSL.
package httpx

import (
	"crypto/tls"
	"net/http"
	"time"
)

// NewClient returns an *http.Client with a sane timeout, optionally skipping
// TLS verification — the Go equivalent of every pythonoperator requests.*
// call's verify=settings.keycloak_verify_ssl kwarg.
func NewClient(verifySSL bool) *http.Client {
	if verifySSL {
		return &http.Client{Timeout: 30 * time.Second}
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in via MYCELIAM_KEYCLOAK_VERIFY_SSL=false
		},
	}
}
