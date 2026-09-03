# deploy-operator

> **Relationship to `goperator/deploy/deployment.yaml`**: that single file
> is the canonical, minimal template. This directory is an alternative way
> to deploy the same operator — more explicit, and it separates the
> Keycloak-only and SPIFFE-bootstrap setups into their own files instead of
> one file with commented-out alternatives. Mainly useful for playing around
> and understanding the two modes side by side; `goperator/deploy/` is still
> the reference starting point.

Deployment manifests for the myceliam operator itself, split by where its
own bootstrap credential for AWS/GCP federation comes from. Both modes
still use Keycloak for the Admin REST API (workload
`clienttype=secret`/`signedjwt` provisioning) — see
[`goperator/README.md`](../goperator/README.md#the-operators-own-identity)
for the full explanation of why these are two independent settings.

- **`oidc/`** — the default: the operator's own Keycloak client is used both
  for the Admin API and for the operator's own AWS/GCP federation token
  (`MYCELIAM_OPERATOR_IDENTITY_SOURCE` left at its `keycloak` default).
- **`spiffe/`** — the operator's own AWS/GCP federation token comes from a
  local SPIRE agent instead (`MYCELIAM_OPERATOR_IDENTITY_SOURCE=spiffe`),
  while it still uses the same Keycloak client for the Admin API. Requires a
  separate, pre-existing AWS/GCP bootstrap trust for this SPIFFE identity,
  and a SPIRE registration entry for the operator's own pod
  (`operator-clusterspiffeid.yaml`) — see the comments in
  `spiffe/spiffe-operator.yaml` for specifics.

## Apply order

1. CRDs (not included here — see
   [`goperator/deploy/crds/`](../goperator/deploy/crds/)):
   ```bash
   kubectl apply -f ../goperator/deploy/crds/
   ```
2. Namespace, ServiceAccount, and RBAC:
   ```bash
   kubectl apply -f operator-rbac.yaml
   ```
3. The operator's own Keycloak credential — exactly one of the two (the
   keypair wins if both exist):
   ```bash
   kubectl apply -f oidc/oidc-client-secret.yaml
   # or
   kubectl apply -f oidc/oidc-tls-secret.yaml
   ```
4. Fill in the `<>` placeholders in whichever operator Deployment matches
   your setup, then apply it:
   ```bash
   kubectl apply -f oidc/oidc-operator.yaml
   # or, for the SPIFFE-bootstrap variant:
   kubectl apply -f spiffe/spiffe-operator.yaml
   kubectl apply -f spiffe/operator-clusterspiffeid.yaml
   ```

Every `<>` in these files is a placeholder — nothing here will run as-is.
