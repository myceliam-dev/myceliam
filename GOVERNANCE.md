# Governance

myceliam is an early-stage project currently maintained by a small group of
maintainers (see [MAINTAINERS.md](MAINTAINERS.md)). This document describes
how the project is run today and how that's expected to evolve as the
community grows.

## Roles

- **Maintainers** have write access to the repository, review and merge
  pull requests, triage issues, and are collectively responsible for the
  project's technical direction. Maintainers are listed in
  [MAINTAINERS.md](MAINTAINERS.md).
- **Contributors** are anyone who opens an issue, submits a pull request, or
  otherwise participates in the project. No special access is required to
  contribute.

## Decision-making

Day-to-day technical decisions (bug fixes, small features, documentation)
are made by lazy consensus: a maintainer proposes a change (typically as a
pull request), and it can be merged once at least one other maintainer has
approved it, or after a reasonable review period with no objections if only
one maintainer is currently active.

Larger changes — new subsystems, breaking changes to the CRD API, changes to
this governance model — should be raised as a GitHub issue or discussion
before implementation, so other maintainers and the community have a chance
to weigh in.

## Becoming a maintainer

Contributors who make sustained, high-quality contributions (code reviews,
pull requests, issue triage, documentation) may be nominated for maintainer
status by an existing maintainer. Maintainers decide on new maintainer
nominations by consensus. As the maintainer group grows, this process will
be formalized further.

## Conflict resolution

Disagreements are expected to be worked out through discussion, consistent
with the [CNCF Community Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md)
(see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)). If maintainers cannot reach
consensus on a technical decision, it's decided by a majority vote of
active maintainers.

## Changes to this document

Changes to this governance model are proposed as a pull request against this
file and require approval from a majority of active maintainers.
