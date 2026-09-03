# Contributing to myceliam

Thanks for your interest in contributing! This project follows the
[CNCF Community Code of Conduct](CODE_OF_CONDUCT.md) — please read it before
participating.

## Repository layout

- `goperator/` — the operator itself (Go module `myceliam`).
- `deploy-operator/` — alternative operator deployment manifests, split by
  identity source.
- `example-oidc-client/` — a standalone example app proving Keycloak-issued
  federation works end to end.
- `example-spiffe-client/` — the SPIFFE/SPIRE-issued counterpart.

Each Go directory is an independent module with its own `go.mod`.

## Building and testing

From `goperator/` (and similarly from either example app's directory):

```bash
go build ./...
go vet ./...
go test ./...
```

## Making a change

1. Open an issue first for anything beyond a small fix, so the change can be
   discussed before you put work into it.
2. Fork the repository and create a branch for your change.
3. Make sure `go build`, `go vet`, and `go test` are all clean.
4. Open a pull request describing what changed and why.

## Sign off your commits (DCO)

Every commit must include a `Signed-off-by` line, certifying that you wrote
the change or otherwise have the right to submit it under the project's
license (the [Developer Certificate of Origin](https://developercertificate.org/)).
Add it automatically with:

```bash
git commit -s -m "your commit message"
```

## Reporting bugs

Open a GitHub issue with what you expected, what actually happened, and
enough detail to reproduce it (Kubernetes/Go version, relevant logs, the
`ServiceAccount`/CR labels involved). For security vulnerabilities, see
[SECURITY.md](SECURITY.md) instead of opening a public issue.
