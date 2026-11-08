# ADR-0010: Hardening target: OpenSSF silver

**Status:** Accepted (2026-11-08).

**Decision:** the repository targets the OpenSSF Best Practices **silver** level, like
presidio-evidence and the other presidio-v flagships:

- governance, code of conduct, contributing guide, architecture and assurance case
  (`GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `ARCHITECTURE.md`, `ASSURANCE.md`);
- CodeQL, bandit, ruff's security rules, `pip-audit`, Atheris fuzzing and OpenSSF Scorecard;
- SHA-pinned actions with least-privilege tokens; Dependabot for dependencies and actions;
- a two-person rule: every change to `main` needs a review from a code owner other than its
  author (`.github/CODEOWNERS`), and releases need a maintainer's approval of the `release`
  environment;
- SSH-signed release tags (`allowed_signers`).

**Not claimed:** an external security audit, reproducible builds, or a second unaffiliated
contributor. Those are gold-level criteria and are not met.
