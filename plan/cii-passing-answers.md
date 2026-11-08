---
status: working sheet
owner: vstantch
target: OpenSSF Best Practices Badge — passing level
project_url: https://github.com/presidio-v/presidio-deident
---

# CII Best Practices — passing-level answer sheet

Answers for <https://www.bestpractices.dev> (passing level), filled from the
evidence in this repository on 2026-11-08. Every cited URL must resolve on `main`
before the answers are submitted.

## Before you start

1. **Register the URL as exactly** `https://github.com/presidio-v/presidio-deident`.
   Scorecard does a literal DB string match. A trailing slash, `www.`, or the
   PyPI URL returns `NotFound` → score 0 despite a real badge.
2. **Log in with GitHub but decline the org grant.** BadgeApp requests `read:org`
   and no code path consumes it.
3. The project is registered as
   [project 16454](https://www.bestpractices.dev/projects/16454), recorded in
   `hardening.toml` (`[badge] bestpractices_id`), and the badge is on the README.
4. The answers below are also in `.bestpractices.json` at the repository root,
   which BadgeApp reads to propose each answer for review.

Shorthand below: `REPO` = `https://github.com/presidio-v/presidio-deident`.

The repository has been public since 2026-11-08 with a fresh history; development
from 0.1.0 to 0.7.0 happened in a private repository and is summarised in
`CHANGELOG.md` and `docs/adr/`. Answers that depend on that period say so.

---

## Basics — project website content

| Criterion | Status | Justification / URL |
|---|---|---|
| `description_good` | **Met** | `REPO#readme` — the README opens with what the project does (de-identify a dataset before licensing it to an AI developer, and sign a release record that the buyer verifies offline) and the problem it addresses (documenting what was removed, what remained, which opt-out and deletion lists were applied, and the declared rights, in counts and hashes only, without claiming the output is anonymous). |
| `interact` | **Met** | Obtaining: README "Install" (`pip install presidio-deident`, PyPI). Feedback and contributing: `REPO/blob/main/CONTRIBUTING.md` (bug reports and feature requests via `REPO/issues`, the PR flow); vulnerability reports: `REPO/blob/main/SECURITY.md`. GitHub shows both files next to the README. |
| `contribution` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md` — documents the fork → branch → PR flow against `main`. |
| `contribution_requirements` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md#requirements-for-acceptable-contributions` — ruff style config, test and coverage policy, security-sensitive-change rules, dependency bar. |

## Basics — FLOSS license

| Criterion | Status | Justification / URL |
|---|---|---|
| `floss_license` | **Met** | `MIT`. |
| `floss_license_osi` | **Met** | `MIT` is OSI-approved. |
| `license_location` | **Met** | URL: `REPO/blob/main/LICENSE` |

## Basics — documentation

| Criterion | Status | Justification / URL |
|---|---|---|
| `documentation_basics` | **Met** | README (Install, the five releaser commands, the one buyer command against the committed sample release, the policy format, quasi-identifier risk, re-releases, formats), `docs/SPEC.md` (record format and verification algorithm), `docs/KEYS.md` (keys, trust-store delivery, rotation), `docs/THREAT-MODEL.md`, `SEMVER.md`, and the decision records in `docs/adr/`. |
| `documentation_interface` | **Met** | The external interface is the `deident` CLI (subcommands, options, exit codes 0/1/2), the `dataset-release@1` record format with its schema `schemas/dataset-release.v1.json`, the `verify --json` result `verify-result@1` and the check names; specified in `REPO/blob/main/docs/SPEC.md` and enumerated in `REPO/blob/main/SEMVER.md`, with usage in the README. The Python modules are documented as not yet a public API. |

## Basics — other

| Criterion | Status | Justification / URL |
|---|---|---|
| `sites_https` | **Met** | The repository (GitHub), the package (PyPI) and the project page `https://www.presidio-group.eu/dataset-release/` are all served over HTTPS. The project runs no hosted service. |
| `discussion` | **Met** | GitHub Issues: `REPO/issues` — searchable, URL-addressable, open, no proprietary client. |
| `english` | **Met** | All docs and issue handling in English. |
| `maintained` | **Met** | Release 0.7.0 on 2026-11-08 (`REPO/releases`, PyPI); PR #2 merged 2026-11-08; CI, CodeQL, Scorecard and Dependabot active. |

## Change control — repository

| Criterion | Status | Justification / URL |
|---|---|---|
| `repo_public` | **Met** | `REPO` |
| `repo_track` | **Met** | git. |
| `repo_interim` | **Met** | Every change lands through a pull request from a pushed branch (direct pushes to `main` are blocked by branch protection), e.g. PR #2; interim work is visible between versions. |
| `repo_distributed` | **Met** | git. |

## Change control — versioning

| Criterion | Status | Justification / URL |
|---|---|---|
| `version_unique` | **Met** | One version in `pyproject.toml` per release; each release is a `vX.Y.Z` tag and one `CHANGELOG.md` entry; PyPI refuses to reuse a version. |
| `version_semver` | **Met** | URL: `REPO/blob/main/SEMVER.md` — semantic versioning with the documented 0.x rules (additive changes are minor, patch releases fix bugs and security defects only); the record and result formats are versioned separately (`@1`, `@2`). |
| `version_tags` | **Met** | Releases are tagged `vX.Y.Z` (`v0.7.0`, `REPO/tags`); the tag is an annotated, SSH-signed tag that GitHub shows as Verified. Versions 0.1.0 to 0.6.0 were never published. |

## Change control — release notes

| Criterion | Status | Justification / URL |
|---|---|---|
| `release_notes` | **Met** | URL: `REPO/blob/main/CHANGELOG.md` — hand-written per version (Added / Changed / Fixed), not VCS log output. |
| `release_notes_vulns` | **N/A** | No publicly known vulnerability (CVE, GHSA or similar) has been fixed in any release; no security advisory exists for this repository. Defects found by the two internal review passes before publication (for example the quadratic email pattern fixed in 0.2.0) are listed under "Fixed" in `CHANGELOG.md`. |

## Reporting — bug reports

| Criterion | Status | Justification / URL |
|---|---|---|
| `report_process` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md#reporting-bugs-and-requesting-features` |
| `report_tracker` | **Met** | GitHub Issues. |
| `report_responses` | **Met** | Met by the documented process. The repository became public on 2026-11-08 and no bug report has been received yet; the issue tracker is empty. |
| `enhancement_responses` | **Met** | Met by the documented process. No enhancement request has been received yet. |
| `report_archive` | **Met** | URL: `REPO/issues?q=is%3Aissue` — public and searchable. |

## Reporting — vulnerability reports

| Criterion | Status | Justification / URL |
|---|---|---|
| `vulnerability_report_process` | **Met** | URL: `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` |
| `vulnerability_report_private` | **Met** | URL: `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` — private GitHub Security Advisory ("Security → Report a vulnerability", private vulnerability reporting enabled) or `security@presidio-group.eu`; acknowledgement within 5 business days (`CONTRIBUTING.md#reporting-a-security-vulnerability`). |
| `vulnerability_report_response` | **N/A** | No vulnerability reports have been received in the last 6 months: no security advisory, draft or published, exists for this repository, which was private until 2026-11-08. |

## Quality — build system

| Criterion | Status | Justification / URL |
|---|---|---|
| `build` | **Met** | Standard PEP 517 build with the `hatchling` backend: `python -m build` (or `uv build`) rebuilds the sdist and wheel from source; `publish.yml` does exactly this. |
| `build_common_tools` | **Met** | pip, `build` and `hatchling`. |
| `build_floss_tools` | **Met** | The entire toolchain is FLOSS. |

## Quality — automated test suite

| Criterion | Status | Justification / URL |
|---|---|---|
| `test` | **Met** | 12 pytest modules under `tests/` (186 tests on 2026-11-08: policy and table readers, detector, release run, verify, history chains, risk and generalisation, Parquet, California DROP lists, CLI, seeded mutation tests, review regressions, and the public contract with the shipped test vectors and the signed sample release). Licensed with the project. How to run: `CONTRIBUTING.md#local-verification`. |
| `test_invocation` | **Met** | `pytest` (configured in `pyproject.toml`; `python -m pytest tests/`). |
| `test_most` | **Met** | CI enforces at least 90% combined line and branch coverage (`--cov-branch --cov-fail-under=90` in `pyproject.toml` `[tool.pytest.ini_options]`). Measured 98.6% on 2026-11-08 (1,295 statements with 11 missed, 462 branches with 13 partial). `tests/test_public_contract.py` verifies the committed signed sample release end to end. |
| `test_continuous_integration` | **Met** | GitHub Actions on every push to `main` and every PR (`.github/workflows/ci.yml`): lint, the test suite with the coverage gate on Python 3.11, 3.12 and 3.13 (Ubuntu), `pip-audit`, and the Atheris fuzz job. All are required checks on `main`. |

## Quality — new functionality testing

| Criterion | Status | Justification / URL |
|---|---|---|
| `test_policy` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md#tests` — changes that add or modify functionality ship with tests in the same PR; bug fixes ship with a regression test that fails before and passes after. |
| `tests_are_added` | **Met** | Example (0.2.0, `CHANGELOG.md`): the first internal review found the email pattern quadratic on long runs of local-part characters; the fix (a lookbehind anchor) shipped with `tests/test_review_fixes.py::test_detector_is_linear_on_long_runs` in the same change. Likewise every 0.5.0 fix from the second review has a test in that file (e.g. `test_parent_to_another_recipient_is_refused`, `test_scrub_keeps_text_without_findings_unchanged`). These changes were made in the private development repository before publication, so the PRs are not linkable; the tests are in the public tree. |
| `tests_documented_added` | **Met** | The policy is stated in the contribution instructions themselves (`CONTRIBUTING.md#tests`). |

## Quality — warning flags

| Criterion | Status | Justification / URL |
|---|---|---|
| `warnings` | **Met** | `ruff check .` and `ruff format --check .` in CI (`ci.yml`, `lint` job). |
| `warnings_fixed` | **Met** | CI fails on any finding; `main` is clean. |
| `warnings_strict` | **Met** | ruff selects `E`, `F`, `W`, `I`, `B`, `UP`, `S` (flake8-bandit security rules) and `SIM`, well beyond ruff's default `E`/`F` subset (`pyproject.toml` `[tool.ruff.lint]`). Exclusions are limited to `tests/` (`S101`, `S105`, `S106`, `S311`, `E501`) and `fuzz/` (`S101`, `SIM105`, `N802`); `src/` has one `noqa` (`B007`, a loop variable read in the `except`). |

## Security — secure development knowledge

| Criterion | Status | Justification / URL |
|---|---|---|
| `know_secure_design` | **Met** | The design is fail closed (an unknown policy key, an unmapped column, unwritable input or unjustified PII in a kept column stops the run; a release verifies only if every check passes), least privilege and least data (no network, no hosted mode, records carry counts and hashes, never values; outputs `0600` in a `0700` directory), complete mediation (every listed file re-hashed on every verify), defence in depth (signature over the record, record over the files, unsigned envelope fields bound to the record) and economy of mechanism (all cryptography from `presidio-evidence` and `cryptography`). Argued in `REPO/blob/main/ASSURANCE.md#3-secure-design-principles-applied`. Two internal review passes were done during development; there has been no external review or security audit. |
| `know_common_errors` | **Met** | `REPO/blob/main/ASSURANCE.md` maps swapped or edited files, edited records and envelopes, cross-dataset replay, path traversal and symlinks, resource exhaustion and value leakage to controls (section 1), and CWE-22, CWE-400/1333, CWE-20, CWE-200/532, CWE-330, CWE-798 and CWE-345/354 to named countermeasures (section 4); `docs/THREAT-MODEL.md` states what a record does and does not prove. |

## Security — cryptographic practices

| Criterion | Status | Justification / URL |
|---|---|---|
| `crypto_published` | **Met** | SHA-256 (FIPS 180-4) for file, policy and list hashes; Ed25519 (RFC 8032) for the release signature (presidio-evidence `evidence-ref@3`); HMAC-SHA256 (RFC 2104) for per-recipient pseudonym-key derivation and pseudonyms. |
| `crypto_call` | **Met** | Ed25519 signing, verification and key generation come from `presidio-evidence` (backed by `cryptography`); SHA-256 and HMAC from the Python standard library (`hashlib.sha256`, `hmac.new`); random keys from `secrets`. No primitive is re-implemented. |
| `crypto_floss` | **Met** | `presidio-evidence` (MIT), `cryptography` (Apache-2.0/BSD), CPython's `hashlib`/`hmac`/`secrets` (PSF). |
| `crypto_keylength` | **Met** | Ed25519 signing keys (about 128-bit security), SHA-256 digests, and a 256-bit pseudonym key from `deident keygen`, all above the NIST 2030 minimum of 112 bits; pseudonyms are HMAC-SHA256 output truncated to 128 bits. The tool does not enforce a minimum length on a pseudonym key the operator supplies from elsewhere. |
| `crypto_working` | **Met** | No MD4, MD5, single DES, RC4 or Dual_EC_DRBG anywhere in the code. |
| `crypto_weaknesses` | **Met** | No SHA-1 and no CBC mode; the project does no encryption. The unkeyed SHA-256 suppression-list format is guessable for low-entropy values; this is a documented limit (`SECURITY.md#known-limits`, ADR-0006), not a security function. |
| `crypto_pfs` | **N/A** | The project implements no key-agreement or network protocol and makes no network calls. |
| `crypto_password_storage` | **N/A** | Stores no passwords. |
| `crypto_random` | **Met** | `deident keygen` (`src/presidio_deident/cli.py`) makes the pseudonym key with `secrets.token_bytes(32)` and the Ed25519 signing key with `presidio_evidence.generate_ed25519_keypair()` (`cryptography`, OS CSPRNG). Ed25519 signing is deterministic and needs no nonce. |

## Security — delivery

| Criterion | Status | Justification / URL |
|---|---|---|
| `delivery_mitm` | **Met** | Distributed over HTTPS from PyPI and GitHub. `publish.yml` publishes through PyPI Trusted Publishing (OIDC, no stored API token) after a required reviewer approves the `release` environment (deployable from `v*` tags only); PyPI files carry PEP 740 attestations. |
| `delivery_unsigned` | **Met** | No hash is fetched over plain HTTP. Release tags are SSH-signed and GitHub-verified; the wheel and sdist carry build-provenance attestations (`gh attestation verify`). |

## Security — known vulnerabilities

| Criterion | Status | Justification / URL |
|---|---|---|
| `vulnerabilities_fixed_60_days` | **Met** | No known unpatched medium+ vulnerabilities. `pip-audit` runs in CI on every push and PR (`ci.yml`, required check `audit`); Dependabot alerts and security updates are enabled, with no open alerts. The only runtime dependency is `presidio-evidence[crypto]` (bringing `cryptography`). |
| `vulnerabilities_critical_fixed` | **Met** | No critical vulnerability has arisen in the project or its dependencies; `pip-audit` would fail CI on one. |

## Security — other

| Criterion | Status | Justification / URL |
|---|---|---|
| `no_leaked_credentials` | **Met** | gitleaks 8.30.1 over the full history on 2026-11-08 (all refs of the working repository, including the pre-public development history: 21 commits): the 12 hits are all the keyword argument `pseudonym_key=ws.pseudo_key` in tests, i.e. false positives. The only key material in the tree is public: the trust stores `examples/sample-trust.json` and `src/presidio_deident/vectors/*trust.json`. GitHub secret scanning with push protection is enabled. |

## Analysis — static

| Criterion | Status | Justification / URL |
|---|---|---|
| `static_analysis` | **Met** | CodeQL for Python with the `security-extended` queries (`.github/workflows/codeql.yml`, results in GitHub code scanning, required check `CodeQL Analyze (Python)`), Bandit over `src/` (required check `Bandit SAST`), and ruff with the `S` (flake8-bandit) rule set in CI. |
| `static_analysis_common_vulnerabilities` | **Met** | CodeQL's Python security queries, Bandit, and ruff's `S` rules (injection, unsafe deserialization, weak hashes, insecure randomness, hard-coded secrets and similar) as required CI checks. |
| `static_analysis_fixed` | **Met** | Findings are fixed before merge; CI blocks on ruff and Bandit findings, and there are no open code-scanning alerts. |
| `static_analysis_often` | **Met** | CodeQL runs on every push and PR to `main`, plus a weekly scheduled run; ruff and Bandit run on every push and PR. |

## Analysis — dynamic

| Criterion | Status | Justification / URL |
|---|---|---|
| `dynamic_analysis` | **Met** | The automated suite exceeds 80% branch coverage (449 of 462 branches fully covered, 2026-11-08; branch coverage is part of the 90% gate) and runs on every PR and release commit through CI. Two Atheris coverage-guided harnesses run in CI on every push and PR (`ci.yml`, required check `fuzz`, 60 s each): `fuzz/fuzz_readers.py` drives arbitrary input through the CSV and JSONL readers and the policy parser, asserting that only `DeidentError` escapes; `fuzz/fuzz_verify.py` replaces a signed release's record with arbitrary bytes and asserts that `verify_release` never raises and passes only for the original record. Seeded mutation tests (`tests/test_mutation.py`) mutate releases, inputs and policies. |
| `dynamic_analysis_unsafe` | **N/A** | The project is pure Python, which is memory-safe; it ships no native code. |
| `dynamic_analysis_enable_assertions` | **Met** | Tests are assertion-based (pytest) and run without `-O`; the fuzz harnesses also run without `-O`, so their assertions are checked. |
| `dynamic_analysis_fixed` | **Met** | No unfixed medium+ findings. The seeded mutation tests found that edited unsigned envelope fields still verified; fixed in 0.3.1 before publication. |

---

## Notes

- Any passing criterion not listed here is answerable **Met** by an existing
  artefact or **N/A** (library vs. website/app). Check `SECURITY.md`,
  `CONTRIBUTING.md` and `ci.yml` before writing anything new.
- Test counts and coverage figures are as of 2026-11-08; update them if the
  suite changes before submission.
- Recommended before submission (not required for passing): link `CONTRIBUTING.md`,
  `SECURITY.md` and the issue tracker from the README, so `interact` does not rely
  on GitHub's sidebar.
