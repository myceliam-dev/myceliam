# deploy-operator

> **Relationship to `goperator/deploy/deployment.yaml`**: that single file
> is the canonical, minimal (Keycloak-only) template. This directory is an
> alternative way to deploy the same operator — more explicit, and it
> separates each identity-provider/bootstrap combination into its own file
> instead of one file with commented-out alternatives. Mainly useful for
> playing around and understanding the different modes side by side;
> `goperator/deploy/` is still the reference starting point.

Deployment manifests for the myceliam operator itself, split first by which
provider is active for workload (`clienttype=secret`/`signedjwt`)
provisioning, then by where the operator's own AWS/GCP federation bootstrap
credential comes from (`MYCELIAM_OPERATOR_PROVIDER`) — see
[`goperator/README.md`](../goperator/README.md#the-operators-own-identity)
for the full explanation of why these are two independent settings. Which
workload provider(s) are active is now determined purely by presence of
their config env vars (`MYCELIAM_KEYCLOAK_URL` /
`MYCELIAM_AUTH0_DOMAIN`+`MYCELIAM_AUTH0_OPERATOR_CLIENT_ID`) — there's no
single "the provider" env var anymore.

- **`keycloak/`** — only `MYCELIAM_KEYCLOAK_URL` set. The operator's own
  Keycloak client is used both for the Admin REST API and, by default, for
  the operator's own AWS/GCP federation token (`MYCELIAM_OPERATOR_PROVIDER`
  left unset, auto-resolving to `keycloak` since it's the only active
  provider). See `spiffe/` below if you'd rather the operator's own
  federation token come from SPIRE instead, while still using this same
  Keycloak client for the Admin API.
- **`auth0/`** — only `MYCELIAM_AUTH0_DOMAIN`/`MYCELIAM_AUTH0_OPERATOR_CLIENT_ID`
  set. Like Keycloak, `internal/oidc/auth0.Provider.GetOperatorToken` is
  implemented, so by default the operator's own Auth0 Application is used
  both for the Management API and (via a separate Resource Server the
  operator provisions itself on first use — `MYCELIAM_AUTH0_OPERATOR_AUDIENCE`)
  for its own AWS/GCP federation token, the same two-roles-one-credential
  shape as `keycloak/`. See `spiffe/` below if you'd rather the operator's
  own federation token come from SPIRE instead (`auth0-operator.yaml` has a
  commented-out block for this). Requires a pre-existing Auth0 tenant and,
  separately, a one-time tenant-wide Action (auto-provisioned by the
  operator on first use — see `internal/oidc/auth0`'s package doc comment,
  not something you apply here).
- **`spiffe/`** — layers on top of `keycloak/` (or `auth0/`): the operator's
  own AWS/GCP federation token comes from a local SPIRE agent instead
  (`MYCELIAM_OPERATOR_PROVIDER=spiffe`), while it still uses a
  Keycloak/Auth0 client for the Admin/Management API (that provider's own
  activation env vars unchanged). Requires a separate, pre-existing AWS/GCP
  bootstrap trust for this SPIFFE identity, and a SPIRE registration entry
  for the operator's own pod (`operator-clusterspiffeid.yaml`) — see the
  comments in `spiffe-operator.yaml` for specifics. `auth0/` can reuse this
  same registration entry and bootstrap trust if you go that route, since
  the operator's own SPIFFE identity doesn't depend on which workload
  provider(s) are active at all.

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
3. The operator's own credential for whichever provider you're using —
   exactly one of the two per provider (the keypair wins if both exist):
   ```bash
   kubectl apply -f keycloak/keycloak-client-secret.yaml
   # or
   kubectl apply -f keycloak/keycloak-tls-secret.yaml

   # for auth0/ instead:
   kubectl apply -f auth0/auth0-client-secret.yaml
   # or
   kubectl apply -f auth0/auth0-tls-secret.yaml
   ```
4. If using SPIFFE for the operator's own identity (optional for both
   `keycloak/` and `auth0/`), the registration entry for the operator's own
   pod:
   ```bash
   kubectl apply -f spiffe/operator-clusterspiffeid.yaml
   ```
5. Fill in the `<>` placeholders in whichever operator Deployment matches
   your setup, then apply it:
   ```bash
   kubectl apply -f keycloak/keycloak-operator.yaml
   # or
   kubectl apply -f spiffe/spiffe-operator.yaml
   # or
   kubectl apply -f auth0/auth0-operator.yaml
   ```

Every `<>` in these files is a placeholder — nothing here will run as-is.
