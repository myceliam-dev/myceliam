# myceliam-operator

[github.com/myceliam-dev/myceliam](https://github.com/myceliam-dev/myceliam)

A Kubernetes-native identity federation control plane: it connects workload
identities — from sources such as SPIFFE and OIDC — to cloud IAM in
environments such as AWS and GCP, and declaratively keeps that trust in
sync.

## Why "myceliam"?

myceliam is a Kubernetes-native identity federation control plane for
managing trust between workloads and external IAM systems. Rather than
issuing or replacing workload identities, it consumes identities that
already exist — such as SPIFFE-issued credentials and OIDC tokens — and
declaratively federates them into external systems such as AWS and GCP. It
abstracts the provider-specific mechanics of establishing that federation
and continuously reconciles the trust relationships it creates, so access
stays correct as workloads and infrastructure change.

Named after *mycelium* — the underground network of fungal threads that
connects otherwise-separate organisms and exchanges nutrients between them,
the root network beneath the visible mushroom. That's the role this operator
plays: Kubernetes, an identity provider (Keycloak or SPIRE), and a cloud
account are three systems that each already know how to trust *something* —
Kubernetes trusts its own ServiceAccount tokens, Keycloak/SPIRE issue JWTs
they'll vouch for, AWS/GCP accept federated tokens from an IdP they trust —
but nothing connects those three trust relationships into one chain by
default. A `ServiceAccount` in namespace `foo` and an IAM role in some AWS
account have no idea the other exists until something wires them together.
myceliam is that wiring: label a `ServiceAccount`, and its Kubernetes
identity extends outward, unbroken, as far as `AwsAccessProfile`/
`GcpAccessProfile` say it should reach.

## The problem this solves

The conventional way to give a pod cloud access is to hand it long-lived
credentials — an AWS access key, a GCP service account JSON key — usually as
a Kubernetes Secret. That Secret has to be minted somewhere, distributed
somehow, and rotated by someone, and every one of those steps is a place a
credential can leak, go stale, or end up broader than the workload actually
needs. Both AWS and GCP have had "federate instead of mint" answers to this
for years — `AssumeRoleWithWebIdentity`, Workload Identity Federation — but
using them means standing up an OIDC provider per identity source, keeping
its JWKS in sync, writing IAM trust conditions by hand, and doing all of that
again for every new namespace or account. In practice almost nobody does this
manually at the pace a real cluster changes, so the static-key path wins by
default, not because it's better.

myceliam exists to make the federated path the *easy* one — declarative,
automatic, and kept in sync on every reconcile — so there's no longer a
reason to reach for a static key at all. A workload's Kubernetes identity is
already the strongest, most Kubernetes-native thing about it; myceliam's job
is just to make sure that identity is legible to whatever's on the other
side of the federation handshake.

## Design principles

- **Every cluster is independently addressable, even sharing backends.**
  `MYCELIAM_CLUSTER_ID` is folded into every realm name and GCP provider ID
  the operator creates, and stamped as an ownership attribute
  (`myceliam.io/cluster-id`) on every Keycloak realm/client it touches. Two
  clusters pointed at the same Keycloak/AWS/GCP backends can have identically
  named namespaces without colliding — and if one cluster's operator ever
  finds a realm or client stamped with a *different* cluster's ID, it refuses
  to touch it rather than silently adopting or overwriting it.
- **Namespace isolation carries through to identity and cloud access, not
  just Kubernetes RBAC.** Each namespace gets its own Keycloak realm (or, for
  SPIFFE, its own SPIFFE ID hierarchy under
  `spiffe://<trust-domain>/ns/<namespace>/...`) and its own per-namespace,
  per-cloud federation audiences. A workload in one namespace can't present a
  token another namespace's cloud trust would accept.
- **Audiences are only as shared as they're safe to be, and no more.** On
  AWS, every `ServiceAccount` gets its own audience
  (`aws-<namespace>-<sa>`) — sharing one audience across SAs in a namespace
  would mean any SA's token satisfies every other SA's trust condition,
  since AWS's federation check has no per-client concept once a token's
  `aud` is a bare string. On GCP, the audience only needs to be
  namespace-shared (`gcp-<namespace>`) — GCP's actual identity narrowing
  comes from `google.subject`/Workload Identity User bindings, not from
  `aud`, so a shared audience there costs nothing.
- **No static, long-lived cloud credentials anywhere.** Every credential a
  workload ultimately gets — AWS temporary credentials via
  `AssumeRoleWithWebIdentity`, a GCP access token via Workload Identity
  Federation — is short-lived and obtained by the workload itself at request
  time. The operator never proxies or hands out cloud credentials; it only
  registers the trust that lets a workload get its own.
- **Declarative and Kubernetes-native.** `ServiceAccount` labels
  (`myceliam.io/client-type`, `myceliam.io/aws-access-profile`, ...) plus
  namespace-scoped `AwsAccessProfile`/`GcpAccessProfile` CRDs are the whole
  interface — no manual per-workload setup in the Keycloak admin console or
  a cloud IAM console, beyond each cloud's one-time bootstrap trust for the
  operator's own identity (see below).
- **Pluggable identity source, same cloud-federation logic either way.**
  `myceliam.io/client-type` picks how a workload proves who it is —
  Keycloak-managed (`secret`/`signedjwt`) or SPIFFE/SPIRE-issued — without
  changing how AWS/GCP federation gets registered or consumed on the other
  side.
- **Registration only.** myceliam establishes trust — realms/clients, IAM
  OIDC providers, Workload Identity providers — never the IAM Role or IAM
  policy binding that actually grants permissions once federated. That stays
  with whoever owns the account/project, same as for any other
  OIDC-federated workload.

Put another way, Kubernetes isn't just where the operator happens to run — a
CRD *is* the desired-state declaration, and the reconcile loop is the whole
mechanism, not a one-time setup script:

```
Kubernetes CRD
      ↓
   myceliam
      ↓
Federation reconciliation
      ↓
   Cloud IAM
```

Add a target to an `AwsAccessProfile`/`GcpAccessProfile`, and myceliam
creates the trust relationship. Remove it, and myceliam removes it. If
something drifts — someone edits a trust policy by hand, rotates a secret
directly in Keycloak — the next periodic reconcile (or the next event on the
resource itself) puts it back. There's no separate "run this once" step to
remember.

## How it works

Label a `ServiceAccount` with `myceliam.io/autoidp=true` and a
`myceliam.io/client-type`, and the operator provisions an identity for it.
What that means depends on the client type — for `secret`/`signedjwt`, it's
a real Keycloak-managed client; for SPIFFE-identified workloads (no
`client-type` label at all, just the SPIFFE annotations below), the identity
already comes from SPIRE, and the operator's job is only to register the
trust needed for AWS/GCP to accept it:

| `myceliam.io/client-type` | Token source | What the operator does |
|---|---|---|
| `secret` | Keycloak, `client_credentials` grant | Creates the realm (namespace-derived) if needed, creates a matching client, writes `client_id`/`client_secret`/`issuer` to `<sa-name>-oidc-credentials` |
| `signedjwt` | Keycloak, RFC 7523 `private_key_jwt` | Same realm/client creation, but authenticated via a JWKS instead of a secret. If `<sa-name>-oidc-credentials` already exists (`kubernetes.io/tls`, e.g. from cert-manager), the operator reads `tls.crt` and pushes its JWKS to Keycloak; otherwise it generates its own RSA keypair and self-signed cert first. Either way, editing `tls.crt` later is picked up and re-uploaded on the next reconcile — no proactive expiry-based rotation, though |
| *(unset, SPIFFE annotations present)* | SPIRE JWT-SVID | No Keycloak client at all — only registers the SPIFFE issuer as a trusted OIDC provider on whichever cloud(s) the SA opted into |

Deleting the `ServiceAccount` deletes its Keycloak client (the realm itself
stays, since sibling SAs in the namespace may still use it — it's deleted
only when the namespace itself is). Setting `myceliam.io/autoidp=false`
instead of deleting the SA makes the operator ignore it entirely — whatever
client, cloud federation, or credentials Secret it already had stays exactly
as-is, and no further label/annotation changes made while dormant are acted
on. Flipping `autoidp` back to `true` reconciles the SA's *current*
labels/annotations from scratch, as if seeing it fresh.

Beyond reacting to `ServiceAccount` create/update/delete events, the operator
also re-reconciles everything on a timer
(`MYCELIAM_RECONCILE_INTERVAL_SECONDS`, default 300s) — this catches drift
that happens entirely on the Keycloak/cloud side (someone rotating a secret
or editing a trust policy by hand) without needing a Kubernetes-side event to
trigger a fix.

A namespace's `ServiceAccount`s are only ever acted on if the namespace
itself is listed in an `AutoidpAllowlist` CR (`deploy/crds/`) — this is
deliberately the one thing the operator never infers from a label alone, so
a stray `myceliam.io/autoidp=true` label in a namespace nobody's reviewed
can't trigger external provisioning on its own.

## ServiceAccount labels

```yaml
metadata:
  labels:
    myceliam.io/autoidp: "true"                    # required — the operator ignores everything else without this
    myceliam.io/client-type: "secret"               # "secret" | "signedjwt" (omit entirely for SPIFFE)
    myceliam.io/aws-access-profile: "awsap-foo"      # name of an AwsAccessProfile in the same namespace
    myceliam.io/gcp-access-profile: "gcpap-foo"      # name of a GcpAccessProfile in the same namespace
  annotations:
    # Only for SPIFFE-identified ServiceAccounts:
    myceliam.io/spiffe-jwt-issuer: "https://spire.example.com"
    myceliam.io/spiffe-id: "spiffe://example.org/ns/<namespace>/sa/<name>"
```

See `internal/models/models.go` (`ParseClientSpec`) and
`internal/cloudmodels/cloudmodels.go` (`ParseCloudFederationSpecs`) for the
exact contract these labels/annotations parse into.

## Cloud IdP federation

The `aws-access-profile`/`gcp-access-profile` labels above are what actually
trigger cloud registration — each names an `AwsAccessProfile`/
`GcpAccessProfile` (`myceliam.io/v1`, namespace-scoped, `deploy/crds/`)
listing the target accounts/projects and the roles/service-accounts within
them the namespace's SAs may federate into:

```yaml
apiVersion: myceliam.io/v1
kind: AwsAccessProfile
metadata:
  namespace: demo
  name: awsap-demo
accounts:
  "123456789012":
    - my-app-role
```

There's no per-SA role selection within a profile — every `ServiceAccount`
referencing a given profile gets identical access to everything it lists;
split into multiple profiles if you need finer granularity per SA.

For each `(profile, ServiceAccount)` pair, the operator:

1. Creates a Keycloak client scope (`<cloud>-<namespace>-<sa>`, attached as
   *optional* — a client only gets a scope's audience mapper in its token
   when it explicitly requests it) carrying an Audience protocol mapper —
   `aws-<namespace>-<sa>` for AWS, `gcp-<namespace>` for GCP (see
   [Design principles](#design-principles) for why these differ).
2. Registers the namespace's realm (or, for SPIFFE SAs, the SA's
   `spiffe-jwt-issuer`) as an IAM OIDC identity provider (AWS) / Workload
   Identity Pool+Provider (GCP) in every account/project the profile lists,
   with that audience in the provider's allowed list, and grants trust on
   every role/service-account listed.

Tearing a `ServiceAccount` down (deletion, or its access-profile label being
removed while `autoidp` stays `true`) always removes that SA's own scope and
trust/impersonation grant immediately. Whether the shared IdP/provider
resource itself also gets deleted depends on whether any *other*
non-SPIFFE `ServiceAccount` in the namespace still references the same
profile — a sibling that's itself mid-deletion doesn't count as still
referencing it, or no SA in a namespace could ever be the one to conclude
it's safe to clean up. Deleting an `AwsAccessProfile`/`GcpAccessProfile` CR
directly deregisters the provider in every account/project it listed;
deleting the namespace cascades the same way.

## The operator's own identity

Everything above needs the operator itself to be able to (a) call
Keycloak's Admin REST API, and (b) get its own AWS/GCP credentials to
register IdPs/providers in the first place. Both of those trace back to one
Keycloak client — not the same as any client it creates on behalf of a
workload `ServiceAccount` — identified by `MYCELIAM_KEYCLOAK_CLIENT_ID`
(default `myceliam-operator`, not a secret, just an identifier).

Unlike the keypairs it generates on behalf of `clienttype=signedjwt`
workloads, the operator never generates a credential for *itself* — it only
reads whichever of two well-known Secrets an admin has already placed in its
own namespace (`MYCELIAM_SYSTEM_NAMESPACE`, default `myceliam-system`). If
both exist, the keypair wins:

```bash
# Option A — client secret (Opaque)
kubectl -n myceliam-system create secret generic myceliam-keycloak-secret \
  --from-literal=client-secret=<redacted>

# Option B — signed-JWT keypair (a plain kubernetes.io/tls secret, tls.crt/
# tls.key only — stays compatible with cert-manager or any other standard
# TLS rotation tooling). Requires the admin to have already uploaded this
# exact certificate to the client's Credentials tab in the Keycloak console
# ("Signed Jwt" authenticator, single certificate — not a JWKS URL): the
# operator can never register its own JWKS the way it does for signedjwt
# workloads, since that call itself requires an already-authenticated admin
# session — exactly what's being bootstrapped here. No `kid` needed either:
# Keycloak's single-certificate client-jwt mode does its own key lookup with
# no kid involved at all (confirmed empirically — including one breaks it
# with "Unable to load public key").
kubectl -n myceliam-system create secret tls myceliam-keycloak-keypair \
  --cert=operator.crt --key=operator.key
```

For its own AWS/GCP credentials, the operator can instead skip Keycloak
entirely and fetch its own SPIRE-issued JWT-SVID
(`MYCELIAM_OPERATOR_IDENTITY_SOURCE=spiffe`) — a setting fully independent
of `MYCELIAM_OIDC_PROVIDER`, which still governs how *workload* identities
get provisioned. Two things have to exist first, and neither is something
the operator can set up for itself (same chicken-and-egg reasoning as its
signed-JWT credential above):

- A **separate** AWS OIDC IdP + IAM role trust update (and/or GCP WLI
  provider), trusting your SPIRE deployment's issuer for the operator's own
  bootstrap identity specifically — distinct from whatever trust already
  exists for individual namespace/SA federation.
- A **SPIRE registration entry for the operator's own pod** (a
  `ClusterSPIFFEID` matching its namespace/ServiceAccount) — without this,
  SPIRE has nothing to issue it, and its `FetchJWTSVID` call fails with
  `PermissionDenied: no identity issued`.

See the commented-out block in `deploy/deployment.yaml` for the exact env
vars and CSI volume mount this needs.

## Deploying

```bash
kubectl apply -f deploy/crds/
kubectl apply -f deploy/rbac.yaml
```

Then create one of the two Secrets described above, and apply
`deploy/deployment.yaml` after filling in its placeholders
(`MYCELIAM_CLUSTER_ID`, `MYCELIAM_KEYCLOAK_URL`, GCP bootstrap values) — or
copy it as a starting point for your own cluster-specific version.

## Configuration reference

All settings are `MYCELIAM_*` environment variables (see
`internal/config/config.go` for the authoritative source). Required, no
default:

| Variable | Notes |
|---|---|
| `MYCELIAM_CLUSTER_ID` | Must be unique across every cluster sharing the same Keycloak/AWS/GCP backends — see [Design principles](#design-principles). |
| `MYCELIAM_KEYCLOAK_URL` | Required when `MYCELIAM_OIDC_PROVIDER=keycloak` (the default). |

Everything else has a default:

| Variable | Default | Purpose |
|---|---|---|
| `MYCELIAM_OIDC_PROVIDER` | `keycloak` | `keycloak` \| `okta` (scaffolded, not usable yet) \| `auth0` (not implemented) \| `none` (SPIFFE-only deployments, no Keycloak/Okta/Auth0 dependency at all) |
| `MYCELIAM_KEYCLOAK_ADMIN_REALM` | `master` | Realm the operator's own Keycloak client lives in |
| `MYCELIAM_KEYCLOAK_CLIENT_ID` | `myceliam-operator` | Identifies the operator's own Keycloak client (not a secret) |
| `MYCELIAM_KEYCLOAK_VERIFY_SSL` | `true` | Set `false` only for self-signed/local test Keycloak instances |
| `MYCELIAM_KEYCLOAK_ADMIN_SIGNEDJWT_ASSERTION_LIFETIME_SECONDS` | `60` | Validity window of each freshly-signed client assertion; only relevant when using `myceliam-keycloak-keypair` |
| `MYCELIAM_SYSTEM_NAMESPACE` | `myceliam-system` | Where the operator looks for its own credential Secrets |
| `MYCELIAM_CREDENTIALS_SECRET_SUFFIX` | `-oidc-credentials` | Suffix for the `<sa-name>{suffix}` Secret the operator writes workload credentials to |
| `MYCELIAM_SIGNEDJWT_KEY_SIZE` | `2048` | RSA key size when generating a `clienttype=signedjwt` workload's keypair |
| `MYCELIAM_SIGNEDJWT_CERT_VALIDITY_DAYS` | `365` | Self-signed cert validity for the same |
| `MYCELIAM_RECONCILE_INTERVAL_SECONDS` | `300` | Periodic full-resync interval |
| `MYCELIAM_KEYCLOAK_OPERATOR_SCOPE` | *(empty)* | Optional client scope requested only for the operator's own cloud-federation token — needed if your Keycloak client requires an explicit scope to pull in AWS/GCP audience mappers |
| `MYCELIAM_OPERATOR_IDENTITY_SOURCE` | `keycloak` | `keycloak` \| `spiffe` — see [The operator's own identity](#the-operators-own-identity) |
| `MYCELIAM_OPERATOR_SPIFFE_AUDIENCE` | *(empty)* | Required when `OPERATOR_IDENTITY_SOURCE=spiffe` — must match the bootstrap AWS IdP/GCP WLI provider's configured audience |
| `MYCELIAM_AWS_OPERATOR_ROLE_NAME` | `myceliam-operator` | Role name the operator assumes in every target AWS account (must be pre-provisioned per account) |
| `MYCELIAM_AWS_OPERATOR_SESSION_NAME` | `myceliam-operator` | `RoleSessionName` on that same call — visible in CloudTrail |
| `MYCELIAM_GCP_OPERATOR_STS_AUDIENCE` | *(empty)* | Full resource name of the bootstrap GCP WLI provider the operator itself federates through — required for GCP support |
| `MYCELIAM_GCP_OPERATOR_SERVICE_ACCOUNT_EMAIL` | *(empty)* | Hub service account the operator impersonates after STS exchange — must already have IAM permissions in every target project |
| `MYCELIAM_GCP_WORKLOAD_IDENTITY_POOL_ID` | `myceliam-operator` | WLI pool every namespace/kind provider is registered into |

## Example apps

Standalone Go modules proving federation actually works end to end, from a
real workload's own perspective (not the operator's) — useful both as a
smoke test and as a reference for writing your own client:

- `../example-oidc-client/` — Keycloak-issued identity (`clienttype=secret`
  or `signedjwt`, auto-detected from which env vars are present, mirroring
  how the operator itself picks between its two credential Secrets), lists
  S3/GCS buckets via `AssumeRoleWithWebIdentity` and GCP's
  STS-then-impersonate flow. One combined token, requesting both audiences
  at once, works for both clouds — Keycloak always stamps a token's `azp`
  claim, so AWS's "reject multi-value `aud` with no `azp`" rule never bites.
- `../example-spiffe-client/` — SPIRE-issued JWT-SVID identity, same
  buckets-listing proof. Fetches **two separate single-audience** SVIDs, one
  per cloud, rather than one combined token — SPIFFE JWT-SVIDs carry no
  `azp` claim at all, so AWS rejects a multi-audience one outright
  (`Token audience contains more than one audience while authorized party
  is not present`); GCP alone would have tolerated a combined token, but
  AWS won't, and an app that needs both has to fetch both.

## Known limitations

- **Registration only.** myceliam creates the AWS IAM OIDC provider / GCP
  Workload Identity provider, never the IAM Role or IAM policy binding that
  actually grants permissions once federated — see
  [Design principles](#design-principles).
- **AWS trust-policy documents have a hard 2048-character cap that AWS
  itself won't raise.** A role referenced by many namespaces/SAs over time
  can accumulate enough `Sid` statements to hit this — `UpdateAssumeRolePolicy`
  then fails with `LimitExceeded: Cannot exceed quota for ACLSizePerRole`.
  Nothing in myceliam prunes stale statements automatically yet; if you hit
  this, the fix is manually removing `Sid`s that no longer correspond to a
  real, current `ServiceAccount`.
- **No proactive, expiry-based cert rotation** for operator-generated
  `signedjwt` workload keypairs — rotation only happens if you edit
  `tls.crt` yourself (or a tool like cert-manager does), which the operator
  then picks up and re-uploads on its next reconcile.
- **Okta is scaffolded, not implemented** (`internal/oidc/okta/`) — every
  method returns `NotImplementedError`-equivalent. **Auth0 isn't implemented
  at all.**
- **A multi-value `aud` claim needs an `azp` claim, or AWS rejects the token
  outright.** Keycloak always provides one; SPIFFE JWT-SVIDs never do. This
  is an AWS behavior, not a myceliam bug, but it shapes how a
  SPIFFE-identified app has to fetch its tokens — see the demo apps above.
- **SPIFFE support assumes you've already stood up SPIRE** (server, agents,
  `spire-controller-manager`, `spiffe-csi-driver`) — myceliam only consumes
  an existing JWT-SVID issuer, it doesn't provision SPIRE itself.

## Where this is headed

Everything above describes what's implemented today: two identity sources
in (Keycloak, SPIRE), two clouds out (AWS, GCP), with access expressed
entirely through `AwsAccessProfile`/`GcpAccessProfile`. The point of the
project, though, is broader than either pairing: myceliam is meant to be an
**orchestrator** — a plug-in point where identity providers on one side and
cloud providers on the other can each grow independently, without either
side having to know about the other. myceliam doesn't issue or replace a
workload's identity, and that's staying fixed — it consumes an identity that
already exists and declaratively federates it outward, wherever that
identity needs to reach.

Authorization itself is deliberately not myceliam's problem to solve —
each cloud already has a mature, native answer to "what is this identity
allowed to do": an IAM role and its attached policies on AWS, a service
account and its granted IAM roles on GCP. myceliam's job stops at
establishing *trust* with those pre-existing resources (registering the
IdP, granting `AssumeRoleWithWebIdentity`/impersonation trust) — what an
identity can actually do once federated is entirely up to whatever policy
is already attached to the role or service account on the cloud side, same
as it would be for any other OIDC-federated identity. That's also why the
authorization-engine idea (a pluggable OPA/OpenFGA/Cedar layer) isn't on
this roadmap: native cloud IAM already *is* that layer.

The relationship a workload has with the cloud side is already many-to-many
in the small — one `ServiceAccount` can federate into several AWS accounts
*and* several GCP projects at once, and several `ServiceAccount`s can share
the same target. The direction is to widen that same graph on both axes,
not replace it: more identity sources in, more cloud providers out.

```
SPIFFE JWT-SVID
       │
       ▼
  payment-api
       │
       ├──── AWS Account A
       ├──── AWS Account B
       ├──── GCP Project X
       ├──── Azure Tenant Y
       └──── OCI Compartment Z
```

Identity providers already share one interface (`oidc.Provider`) that
Keycloak and Okta's scaffold both implement — adding a new one is writing a
new implementation, not restructuring what's there. Cloud providers are
parallel packages today (`internal/cloudproviders/aws`,
`internal/cloudproviders/gcp`) rather than a currently-unified interface;
tightening that into the same kind of pluggable shape as the identity side
is part of the work ahead of adding a third.

Concretely, on the roadmap:

- **Cloud providers**: Azure and Oracle Cloud Infrastructure (OCI),
  alongside AWS/GCP already implemented.
- **Identity providers**: finishing Okta (scaffolded in
  `internal/oidc/okta/`, not yet usable — every method is a stub today) and
  adding Auth0, alongside Keycloak/SPIFFE already implemented.

Neither list changes the shape of what's here already — `AwsAccessProfile`/
`GcpAccessProfile`-style CRDs stay the interface, `ServiceAccount` labels
stay how a workload opts in, and the reconcile loop stays the mechanism.
Growing either list is additive, not a redesign.
