---
status: working sheet
owner: vstantch
target: OpenSSF Best Practices Badge — SILVER level (on top of passing)
project_url: https://github.com/presidio-v/presidio-deident
related:
  - cii-passing-answers.md
---

# CII Best Practices — SILVER answer sheet

Answers for the **silver** tab at
<https://www.bestpractices.dev/en/projects/16454>, filled from the evidence in this
repository on 2026-11-08. It covers only the criteria silver *adds* on top of
passing; passing answers carry over unchanged (see `cii-passing-answers.md`).

**Silver:** every criterion below is answered Met or N/A.

Each row shows the **Status** to set in the dropdown and the **Justification** to
paste. `REPO` = `https://github.com/presidio-v/presidio-deident`.

## Badge embed

Silver uses the **same** embed code as passing; the badge image renders the
current level. It is on the README:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16454/badge)](https://www.bestpractices.dev/projects/16454)
```

## Backing docs

- `GOVERNANCE.md` — governance model, roles, continuity
- `ARCHITECTURE.md` — components, core flow, trust boundaries
- `ASSURANCE.md` — consolidated security assurance case (`assurance_case`)
- `allowed_signers` — public release signing key for local tag verification
- `CONTRIBUTING.md` — DCO sign-off requirement
- `SECURITY.md` — supported versions, reporting, how to verify releases and obtain signing keys
- `README.md` — roadmap table; `PRESIDIO-REQ.md` — version plan and out-of-scope list

---

## Governance & continuity

| Criterion | Status | Justification to paste |
|---|---|---|
| `dco` | **Met** | Contributions must carry a DCO `Signed-off-by` line (`git commit -s`), documented at `REPO/blob/main/CONTRIBUTING.md#licensing-and-developer-certificate-of-origin-dco`; checked in review (there is no automated DCO check). Inbound = outbound `MIT`. The two commits on `main` so far are by the maintainer for the copyright holder (PRESIDIO Group) and carry no sign-off line. |
| `code_of_conduct` | **Met** | Contributor Covenant at `REPO/blob/main/CODE_OF_CONDUCT.md` (standard location). |
| `governance` | **Met** | Maintainer-led, single-steward model documented at `REPO/blob/main/GOVERNANCE.md`: ordinary changes decided on the PR, security-relevant changes (`verify.py`, `release.py`, `_detect.py`, `tables.py`, `policy.py`, `schemas/`, `docs/SPEC.md`, the sample release) need a written rationale and may not weaken a default, compatibility changes follow `SEMVER.md`, disagreements escalate to PRESIDIO Group. |
| `roles_responsibilities` | **Met** | Key roles (steward org, maintainer, security contact, release manager, contributor) documented at `REPO/blob/main/GOVERNANCE.md#roles-and-responsibilities`. |
| `access_continuity` | **Met** | `REPO/blob/main/GOVERNANCE.md#project-continuity`: the repository belongs to the `presidio-v` organisation; publishing uses Trusted Publishing (no personal token); the `release` environment has two required reviewers (`vstantch`, `ceoofcyber`), either of whom can approve a publish; the release signing key is in the organisation password manager, with Bitwarden Emergency Access to a designated trustee who can take over the owner credentials and the key and grant access to another member. The release steps are documented, so another authorised engineer can cut a release within a week. |
| `bus_factor` (SHOULD) | **Met** | Two people review, merge and approve releases (`vstantch`, `ceoofcyber`, both code owners and `release`-environment reviewers); repository ownership, the signing key and the release flow are organisation-held, documented, and covered by the emergency-access policy. See `REPO/blob/main/GOVERNANCE.md#project-continuity`. |

## Documentation

| Criterion | Status | Justification to paste |
|---|---|---|
| `documentation_roadmap` | **Met** | `REPO#roadmap` has a dated "Next 12 months (to November 2027)" section: the first design-partner release and `dataset-release@2`, moving the schema to presidio-evidence, the shared PII package, DROP composite lists, the recipient-risk statement after legal review, and an external review before 1.0. |
| `documentation_architecture` | **Met** | `REPO/blob/main/ARCHITECTURE.md` — components (one row per module), the run and verify flows, and five trust boundaries. |
| `documentation_security` | **Met** | `REPO/blob/main/SECURITY.md` (security properties, known limits, reporting, release verification), `REPO/blob/main/docs/THREAT-MODEL.md` (what a record proves and does not, attacks it stops, residual risks), `REPO/blob/main/ASSURANCE.md`, `REPO/blob/main/docs/KEYS.md`, `REPO/blob/main/ARCHITECTURE.md#trust-boundaries`, and the design rationale in `docs/adr/` (ADR-0001 to ADR-0011). |
| `documentation_quick_start` | **Met** | README "Install" (`pip install presidio-deident`), "Releaser: five commands" (`inspect`, `policy-init`, `keygen`, `run`, `verify`) and "Buyer: one command", which verifies the committed signed sample release (`deident verify examples/sample-release --trust examples/sample-trust.json`). |
| `documentation_current` | **Met** | Docs are updated in the same PR as the code they describe (`CHANGELOG.md` per version, `SEMVER.md`, `docs/SPEC.md` whose key table a test keeps in step with the schema, ADRs, `PRESIDIO-REQ.md` delivery status), and the README, `SECURITY.md` and `SEMVER.md` describe the current 0.7 line. |
| `documentation_achievements` | **Met** | The README front page shows and links the OpenSSF Best Practices badge (project 16454) next to the OpenSSF Scorecard badge; the badge image renders the current level. |

## Change control & reporting

| Criterion | Status | Justification to paste |
|---|---|---|
| `contribution_requirements` | **Met** | `REPO/blob/main/CONTRIBUTING.md#requirements-for-acceptable-contributions` — style, tests, security-change rules, dependency bar. |
| `report_tracker` | **Met** | GitHub Issues: `REPO/issues`. |
| `maintenance_or_update` | **Met** | `REPO/blob/main/SECURITY.md#supported-versions` states the supported line (0.7.x; 0.7.0 is the first published version). `REPO/blob/main/SEMVER.md` gives the upgrade path: a record that verifies keeps verifying in later 0.x versions, every record format verifies for the life of the project, patch releases fix bugs and security defects only, and users pin a minor version and re-verify the committed sample after each upgrade. |
| `vulnerability_report_credit` | **N/A** | No vulnerability report has been received or resolved in the last 12 months; no security advisory exists for this repository. `GOVERNANCE.md#roles-and-responsibilities` assigns reporter credit to the security contact. |
| `vulnerability_response_process` | **Met** | Intake by private GitHub Security Advisory or `security@presidio-group.eu` (`REPO/blob/main/SECURITY.md#reporting-a-vulnerability`); acknowledgement within 5 business days (`CONTRIBUTING.md#reporting-a-security-vulnerability`); the security contact triages, coordinates the fix, the advisory and reporter credit (`GOVERNANCE.md#roles-and-responsibilities`); a verification defect ships as a patch release with an advisory (`SEMVER.md`). |

## Quality & testing

| Criterion | Status | Justification to paste |
|---|---|---|
| `tests_documented_added` | **Met** | `REPO/blob/main/CONTRIBUTING.md#tests` states the policy that changes adding/modifying functionality ship with tests in the same PR. |
| `test_policy_mandated` | **Met** | Formal written policy at `REPO/blob/main/CONTRIBUTING.md#tests`: functionality changes ship with tests; bug fixes include a regression test that fails before the fix. Enforced in code-owner review and by the 90% line-and-branch coverage gate. |
| `automated_integration_testing` | **Met** | `REPO/blob/main/.github/workflows/ci.yml` runs the full suite on every push and PR on Python 3.11, 3.12 and 3.13 (Ubuntu) with the Parquet and parity extras installed, including end-to-end run-then-verify tests, re-release chains (`tests/test_history.py`), the committed signed sample release and the shipped pass/fail vectors (`tests/test_public_contract.py`), the detector parity test against presidio-hardened-x402, and the Atheris fuzz job. All are required checks on `main`. |
| `regression_tests_added50` | **Met** | Policy requires a regression test with every bug fix. All fixes in the last 6 months were made before publication (0.2.0, 0.3.1 and 0.5.0 in `CHANGELOG.md`), and each carries a regression test in the public tree: the 0.2.0 and 0.5.0 review fixes in `tests/test_review_fixes.py` (e.g. `test_detector_is_linear_on_long_runs`, `test_record_fields_are_checked`, `test_parent_to_another_recipient_is_refused`), and the 0.3.1 envelope binding in `tests/test_mutation.py` and the shipped vector `src/presidio_deident/vectors/envelope-mismatch`. The PRs are in the private development repository and are not linkable. |
| `test_statement_coverage80` | **Met** | CI gate: at least 90% combined line and branch coverage (`--cov-branch --cov-fail-under=90` in `pyproject.toml`, applied by every `test` job in `.github/workflows/ci.yml`). Statement coverage measured 99.2% on 2026-11-08 (11 of 1,295 statements missed). |
| `warnings_strict` | **Met** | ruff with `E`, `F`, `W`, `I`, `B`, `UP`, `S` (flake8-bandit) and `SIM`; exclusions limited to `tests/` and `fuzz/`, one `noqa` in `src/`. Bandit over `src/` as a separate required check. CI fails on any finding. |
| `coding_standards` | **Met** | `REPO/blob/main/CONTRIBUTING.md#style` — ruff lint and format, configured in `pyproject.toml` (line length 100, target Python 3.11, rule sets listed). |
| `coding_standards_enforced` | **Met** | `ruff check` and `ruff format --check` run in CI on every PR, in the required check `lint`. |
| `installation_common` | **Met** | `pip install presidio-deident` (or `pip install 'presidio-deident[parquet]'` for Parquet) from PyPI. |
| `installation_development_quick` | **Met** | `REPO/blob/main/CONTRIBUTING.md#local-verification` — create a venv, `pip install -e ".[dev]"`, then the ruff and pytest commands. |
| `build_repeatable` (SHOULD) | **Met** | The release is bit-for-bit reproducible: rebuilding `v0.7.0` from the tagged source (`git archive v0.7.0`, `uv build --wheel --sdist`, macOS) on 2026-11-08 gave a wheel (`6b7c2749…5ee6`) and an sdist (`7be28dac…298b`) whose SHA-256 match the PyPI files exactly. The package is pure Python built by `hatchling` (`>=1.31,<2`); the release build installs `build` unpinned, so reproducing a later release assumes a compatible backend version. |
| `build_standard_variables` | **N/A** | A pure-Python package built by `hatchling`; no compiler or linker is invoked. |
| `build_preserve_debug` | **N/A** | No compiled artefacts; the wheel is pure Python (`py3-none-any`). |
| `build_non_recursive` | **N/A** | A single PEP 517 build; there is no make or subdirectory build. |
| `installation_standard_variables` | **N/A** | Installed via pip; `DESTDIR`-style conventions do not apply. |

## Dependencies & components

| Criterion | Status | Justification to paste |
|---|---|---|
| `external_dependencies` | **Met** | Listed machine-readably in `pyproject.toml`: one runtime dependency (`presidio-evidence[crypto]>=0.5.1,<0.6`, which brings `cryptography`), and the `parquet` (`pyarrow`), `parity` and `dev` extras. There is no lockfile. A CycloneDX SBOM (`sbom.cdx.json`) is generated by `publish.yml` and attached to each GitHub release. |
| `updateable_reused_components` | **Met** | Dependencies are PyPI packages installed by pip; Dependabot tracks pip and GitHub Actions updates. The one vendored component, the structural PII detector from presidio-hardened-x402 (ADR-0003), is checked against its upstream by `tests/test_detect.py::test_parity_with_x402` in CI, so an upstream change shows up as a failing test; replacing it with a shared package is planned. |
| `interfaces_current` | **Met** | Dependencies are kept current by Dependabot (pip, Actions) with security updates enabled; ruff's `UP` rules flag outdated Python idioms; no deprecated FLOSS interface is used where a current one exists. |

## Security

| Criterion | Status | Justification to paste |
|---|---|---|
| `assurance_case` | **Met** (URL required) | URL: `REPO/blob/main/ASSURANCE.md`. Threat table with out-of-scope assumptions, the five trust boundaries of `ARCHITECTURE.md#trust-boundaries`, the secure-design-principles argument and the common-weakness argument (CWE-mapped). It states that two internal review passes were done and that there has been no external review or security audit. |
| `implement_secure_design` | **Met** | Fail-safe defaults: an unknown policy key, an unmapped or missing column, input that cannot be written back faithfully, unjustified PII in a kept column or a leftover `.partial` stops the run; every verify check must pass and malformed input is a failed check. Complete mediation: every listed file is re-hashed on every verify; nothing is cached. Least privilege: no network, no hosted mode, no values in any output; files `0600` in a `0700` directory. Defence in depth: signature over the record, record over the files, unsigned envelope fields bound to the record, `history` binding releases into one chain. Economy of mechanism: Ed25519 and SHA-256 via `presidio-evidence`/`cryptography` and the stdlib, no bespoke crypto, one runtime dependency. See `REPO/blob/main/ASSURANCE.md#3-secure-design-principles-applied`. |
| `input_validation` | **Met** | Input data, policies, lists and received releases are untrusted. `policy.py` rejects unknown keys, unmapped columns and PII in free text (bounded to 512 characters); `tables.py` refuses non-UTF-8, lone surrogates, `NaN`/`Infinity`, nested, binary and decimal values and malformed CSV, naming row and column but never the value; `verify.py` accepts only plain-basename file names, refuses symlinks, size-bounds JSON and matches identifiers and timestamps in full before use. See `ARCHITECTURE.md#trust-boundaries`. |
| `hardening` | **Met** | Key files are written `0600`, never overwritten, and refused if group- or world-readable; outputs are `0600` in a `0700` directory, written to `<out>.partial` and renamed only after signing; symlinks and oversized JSON are refused; detector patterns are linear-time; errors never echo values. Supply chain: SHA-pinned GitHub Actions with least-privilege `permissions:`, Trusted Publishing behind a reviewer-gated `release` environment limited to `v*` tags, branch protection on `main` (code-owner review, last-push approval, admins included, linear history, 8 required checks), secret scanning with push protection. |
| `crypto_weaknesses` | **Met** | Security functions use SHA-256, Ed25519 and HMAC-SHA256 only; no MD5, SHA-1 or DES. |
| `crypto_algorithm_agility` (SHOULD) | **Met** | The signature algorithm is a per-signer trust-store field (`alg`, presidio-evidence `trust-store@1`), and the pseudonym scheme is recorded in each record (`hmac-sha256-128/v1`), so a new algorithm is a new identifier rather than a silent change. The file-hash function (SHA-256) is fixed by `dataset-release@1`; replacing it would be a new format (`@2`) verified side by side with `@1` (`SEMVER.md`), not a runtime switch. |
| `crypto_credential_agility` | **Met** | No key is in the source tree (only public trust stores for the sample and the test vectors). Keys are files supplied at run time (`--sign-key`, `--pseudonym-key`); trust stores are supplied by the buyer, and a signer may list several public keys, so a signing key rotates without a new release (`docs/KEYS.md`, tested in `tests/test_history.py`). Rotating the pseudonym key is possible but changes every pseudonym, as documented. |
| `crypto_used_network` | **N/A** | The project makes no network calls. |
| `crypto_tls12` | **N/A** | No network communication. |
| `crypto_certificate_verification` | **N/A** | No TLS client. |
| `crypto_verification_private` | **N/A** | No network communication. |
| `signed_releases` | **Met** | The wheel and sdist carry GitHub build-provenance attestations (`gh attestation verify <file> --repo presidio-v/presidio-deident`, bundle attached as `provenance.intoto.jsonl`), PyPI files carry PEP 740 attestations from Trusted Publishing, and release tags are SSH-signed with the public key in `REPO/blob/main/allowed_signers`. Documented at `REPO/blob/main/SECURITY.md#verifying-releases-and-obtaining-public-signing-keys`. Checked for `v0.7.0` on 2026-11-08 (wheel and sdist attestations and the tag signature verify). |
| `version_tags_signed` | **Met** | The release tag `v0.7.0` is SSH-signed with the organisation release key and shown as Verified on GitHub; `git -c gpg.ssh.allowedSignersFile=allowed_signers verify-tag v0.7.0` checks it locally. |
| `sites_password_security` | **N/A** | The project runs no site that authenticates users and stores no passwords. |

## Analysis & monitoring

| Criterion | Status | Justification to paste |
|---|---|---|
| `static_analysis_common_vulnerabilities` | **Met** | CodeQL for Python with `security-extended` queries (`REPO/blob/main/.github/workflows/codeql.yml`) on every push/PR and weekly, Bandit over `src/`, and ruff's `S` (flake8-bandit) rules, all required checks; OpenSSF Scorecard (`scorecard.yml`) weekly and on every push to `main` for supply-chain posture. |
| `dynamic_analysis_unsafe` | **N/A** | The project is pure Python, which is memory-safe, and ships no native code. The Atheris harnesses (`fuzz/fuzz_readers.py`, `fuzz/fuzz_verify.py`) run in CI on every push and PR regardless. |
| `dependency_monitoring` | **Met** | Dependabot (pip, GitHub Actions) with security updates enabled; `pip-audit` on every push and PR (`ci.yml`, required check `audit`); OpenSSF Scorecard weekly. |

## Accessibility & internationalization

| Criterion | Status | Justification to paste |
|---|---|---|
| `accessibility_best_practices` | **N/A** | A command-line tool and library with no graphical or end-user UI; output is plain text or JSON. |
| `internationalization` | **N/A** | No user-facing localizable UI; CLI messages are short English diagnostics for operators. |

---

## Notes

- Any silver criterion **not** listed here carries over unchanged from the passing
  sheet.
- `bus_factor`, `build_repeatable` and `crypto_algorithm_agility` are SHOULD
  criteria.
