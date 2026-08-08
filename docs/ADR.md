# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for ZQM-Computing/swarm.

## What is an ADR?

An ADR captures a significant architectural decision made in this project, including:
- The context and problem being addressed
- The decision that was made
- The consequences of that decision

## Index

| # | Title | Status | Date |
|---|-------|--------|------|
| 1 | Use GitHub Actions for CI/CD | Accepted | 2026-08-08 |
| 2 | Adopt ruff for linting and formatting | Accepted | 2026-08-08 |
| 3 | Enforce branch protection on public repos | Accepted | 2026-08-08 |
| 4 | Standardize repository metadata and topics | Accepted | 2026-08-08 |

## Creating a New ADR

1. Copy `templates/adr-template.md` to `docs/adr-{NN}-{short-title}.md`
2. Fill in context, decision, and consequences
3. Submit a PR with the new ADR

## References

- [Michael Nygard's ADR pattern](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
- [ADR GitHub organization](https://adr.github.io/)
