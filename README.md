# myceliam

[github.com/myceliam-dev/myceliam](https://github.com/myceliam-dev/myceliam)

A Kubernetes-native identity federation control plane: it connects workload
identities — from sources such as SPIFFE and OIDC — to cloud IAM in
environments such as AWS and GCP, and declaratively keeps that trust in
sync. See [`goperator/README.md`](goperator/README.md) for the full
documentation — architecture, configuration reference, and deployment guide.

[![Watch the demo video](https://img.youtube.com/vi/FAIoXn2n9iE/hqdefault.jpg)](https://youtu.be/FAIoXn2n9iE)

## Repository layout

- [`goperator/`](goperator/) — the operator itself.
- [`deploy-operator/`](deploy-operator/) — an alternative, more explicit set
  of operator deployment manifests, split by identity source; see its own
  README for how it relates to `goperator/deploy/`.
- [`example-oidc-client/`](example-oidc-client/) — a standalone example app
  proving Keycloak-issued federation works end to end, listing real S3/GCS
  buckets with credentials obtained purely through federation.
- [`example-spiffe-client/`](example-spiffe-client/) — the same proof, for a
  SPIRE-issued identity.

## Status

Early-stage — exercised end-to-end against real Keycloak, SPIRE, AWS, and
GCP, but not yet hardened for production use. See
[`goperator/README.md`'s "Known limitations"](goperator/README.md#known-limitations)
before relying on it.

## Community

- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — myceliam follows the
  [CNCF Community Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to build, test, and submit changes.
- [GOVERNANCE.md](GOVERNANCE.md) — how the project is run and how decisions
  get made.
- [MAINTAINERS.md](MAINTAINERS.md) — who maintains this project.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
