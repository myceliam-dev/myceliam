# Security Policy

## Reporting a vulnerability

Please **do not** report security vulnerabilities through public GitHub
issues.

Instead, use GitHub's private vulnerability reporting: go to the
[Security tab](../../security/advisories/new) of this repository and open a
new draft security advisory. This reaches maintainers directly without
disclosing the issue publicly.

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce it, or a proof of concept.
- The affected component (the operator itself, or one of the example apps)
  and version/commit.

## Response

Maintainers will acknowledge new reports as soon as possible and work with
you to understand and address the issue. Once a fix is available, we'll
coordinate on disclosure timing before any public write-up.

## Scope

myceliam establishes federation trust between Kubernetes workloads and
external identity/cloud systems (Keycloak, SPIRE, AWS IAM, GCP IAM) — issues
in how that trust is established, validated, or torn down (for example, a
token being accepted by a cloud provider when it shouldn't be) are
considered security-relevant even if they don't look like a "classic"
vulnerability.
