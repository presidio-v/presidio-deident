# Presidio-Hardened Toolkit: presidio-deident

## Overview

`presidio-deident` de-identifies a dataset and produces a **signed dataset-release
record** for it. The use case: a data broker (or the company that owns the data) licenses
a dataset to a frontier AI lab or another AI developer. Before the data leaves the
releaser's environment, the toolset removes or pseudonymises direct identifiers, applies
opt-out and deletion lists, reports quasi-identifier risk, and records the declared
sources and rights. The lab verifies the record **offline**, with a free open-source
verifier, without an account and without trusting PRESIDIO.

It is the toolset behind the website offering **Dataset Release**
(`www.presidio-group.eu/dataset-release/`).

**Three roles:**

| Role | Who | What they run |
|---|---|---|
| Releaser | broker, marketplace, or the data-owning company | `deident` on their own infrastructure, with their own key |
| Verifier | the lab's data-procurement or legal team | `presidio-evidence verify` only (no spaCy, no pandas) |
| PRESIDIO | consulting, design partner | sees schemas, policies and signed records (hashes, counts). **Never the records** |

**Overriding rule: the record documents, it does not conclude.** It states which actions
were taken, with counts, under which policy, for which recipient. It never states that the
output is "anonymous", "GDPR-compliant" or "Safe Harbor de-identified". Whether data is
personal for a given recipient (CJEU C-413/23 P, *EDPS v SRB*) is a legal question for the
releaser and its counsel. The recipient-risk statement is the releaser's declaration, not
PRESIDIO's opinion.

**Design constraint: PRESIDIO never handles the data.** This toolset therefore:

- runs only in the releaser's environment;
- has no hosted mode, and dataset content is never sent to a PRESIDIO service;
- is tested on synthetic data only.

Engagement intake accepts schemas, data dictionaries and contracts, and synthetic sample
rows at most.

**Naming.** The working name and local folder is `presidio-deident`. Before the first
PyPI release, decide between this name and `presidio-hardened-deident`, which would
follow the family namespace. `presidio-evidence` is a precedent for dropping `hardened`.

## Reuse map

| Need | Existing component | Status |
|---|---|---|
| PII detection in free text and nested dicts | `presidio_x402.PIIFilter` (presidio-hardened-x402 ≥0.14). Regex mode covers EMAIL, US_SSN, CREDIT_CARD, PHONE, IBAN and IP. NLP mode uses Microsoft Presidio and spaCy, English only. Unicode and escape normalisation | shipped; regex part **vendored** into `_detect.py` (ADR-0003) |
| Canonical hashing, signing, trust stores, offline verify, provenance DAG | `presidio-evidence` ≥0.5.1: `content_hash`, `sign_evidence_v3`, `verify_envelope`, `load_trust_store`, `parents` (ADR-0002), subject binding (ADR-0004) | shipped |
| Ingest ledger with source and scrubbed hashes and per-entity counts | `presidio_ai.ingest.ingest_records`, `presidio_ai.ledger` (presidio-hardened-ai ≥0.32) | shipped |
| DP fine-tuning on the released data, ε budget, n-of-m authorisation | `pai` DP-SGD, `dp-budget`, `dp-authorize` | shipped |
| A gate before training: "verified release present" | `presidio-hardened-ikigov-assess` (`iga`) gate certificates | shipped (new gate item needed) |
| Training-run evidence that names its data | `presidio-hardened-arch-translucency` `train-evidence-emit` (training-run@1) | shipped (parents field needed) |
| Repository hardening, OpenSSF badge | `presidio-hardened-repo` skill | shipped |

**New work:**

- tabular and column semantics;
- quasi-identifier risk;
- keyed pseudonymisation;
- suppression lists;
- the `dataset-release@1` schema;
- Croissant and Data Provenance Standards exports;
- the recipient-risk statement.

**Split.** Everything a *verifier* needs goes into `presidio-evidence`, so a lab installs one
small package. Everything that *touches data* goes into `presidio-deident`:

| Lives in `presidio-evidence` | Lives in `presidio-deident` |
|---|---|
| `dataset-release@1` item schema | readers, column policy engine, transforms |
| multi-file (Merkle) content hash | suppression-list application |
| `verify --files <dir>`: re-hash the released files against the record | QI risk report, recipient-risk questionnaire |
| | record assembly and signing (via evidence), exports |

`PIIFilter` lives in x402, a payments package whose base dependencies include presidio-analyzer and spaCy. v0.1 vendors its regex detector instead (ADR-0003). A shared stdlib-only `presidio-hardened-pii` core would remove the copies in x402, `pai` and deident.

## Mandatory Presidio Security Extensions

- **No values in evidence.** Records, logs and reports carry hashes, counts and column
  names, never cell values. A test asserts this for every output.
- **Keyed pseudonymisation:**
  - The transform is HMAC-SHA256 with a releaser-held key, loaded from a 0600 file or an
    env var; the key is never written to output.
  - A per-recipient key derivation stops two releases to different labs from being joined
    on pseudonyms.
- **Hashed suppression:** opt-out and deletion lists (e.g. California DROP) are matched by
  keyed hash. The record carries the list's hash, date and match count, never the
  entries.
- **Fail-closed policy:**
  - Every column of the input must appear in the policy.
  - An unknown column stops the run; it is not passed through.
  - `keep` on a column the detector flags as direct-identifier needs an explicit
    `justification:` string, which is recorded.
- **Deterministic output:** the same input, policy and key produce byte-identical output and
  the same record hash, so a release can be re-run and checked.
- **Offline and local only:** no network calls during a run, and no telemetry.
- **Supply chain:**
  - SHA-pinned actions, `pip-audit` in CI, CodeQL, Scorecard (a library: dependencies are
    ranges, not a lockfile);
  - Atheris fuzzing of the readers (`import atheris`);
  - SSH-signed release tags;
  - Trusted Publishing with provenance.

## Technical Requirements

- Python 3.11+ (follows presidio-evidence), `src/` layout, `uv`, ruff, pytest with
  coverage floors of 90% statement and 80% branch.
- Readers: CSV and JSONL (stdlib, streamed). Parquet later via a `pyarrow` extra. No pandas.
- Policy: TOML, validated in code (ADR-0002). Actions are `drop | keep | pseudonymise |
  generalise | scrub_text`.
  - `generalise` covers date→year/month, postcode truncation, numeric binning and top/bottom
    coding.
- CLI `deident`: `inspect`, `policy-init`, `keygen`, `run`, `verify`, `croissant`, and from
  v0.2 `risk`.
- Synthetic test data only (`tests/conftest.py`, `examples/`).
- License MIT. Hardened with `presidio-hardened-repo` from the first public commit.

## Decisions taken while building (2026-11-08)

Decisions are recorded in `docs/adr/`.

- **Policy format:** TOML (stdlib) instead of YAML plus JSON Schema. See ADR-0002.
- **PII detection:** vendored from x402 instead of a dependency, because x402 pulls
  presidio-analyzer and spaCy. See ADR-0003.
- **Release layout:** `release.json` (the record) plus `release.evidence.json` (an
  `evidence-ref@3` envelope). The draft schema stays in deident for now. See ADR-0004.
- **Pseudonyms:** HMAC-SHA256 per pseudonym domain (default: the recipient), 128 bits, with
  optional normalisation. See ADR-0005.
- **Suppression lists:** plain or unkeyed SHA-256, never stored in the record. See ADR-0006.
- **Policy hash:** `policy_sha256` is the hash of the policy file's bytes.
- **Accepted value types:** only strings and integers are pseudonymised or matched; anything
  else stops the run.
- **Env-var key source:** cut for v0.1. Keys come from `0600` files only.

## v0.1.0: release record, MVP — **Delivered 2026-11-08**

- [x] `deident inspect`: columns, missing values, detected types and suggested actions,
  counts only.
- [x] `deident policy-init`: a skeleton with every column.
- [x] `deident keygen`: a signing key and a pseudonym key (`0600`) and the trust store.
- [x] `deident run`:
  - streams the input and applies `drop`, `keep` (residual scan, justification gate),
    `pseudonymise` and `scrub_text`, plus plain and SHA-256 suppression lists;
  - writes atomically through `<out>.partial`.
- [x] The `dataset-release@1` record (draft JSON Schema in `schemas/`), signed as an
  `evidence-ref@3` envelope.
- [x] `deident verify`:
  - checks the signature, subject binding, record hash, row arithmetic, `parents`
    format, file hashes and sizes;
  - refuses path traversal and symlinks; offers `--json`.
- [x] `deident croissant`: a minimal Croissant pointer to a verified release.
- [ ] Published spec and sample. These wait on ADR-0008 (publishing).

## v0.2.0: quasi-identifier risk and generalisation — **Delivered 2026-11-08**

- [x] `deident risk` and the record's `risk` section, over declared quasi-identifier
  columns, with integers only:
  - the number of classes, `min_k` and the unique rows;
  - rows by class size (1, 2, 3–4, 5–9, 10–99, 100+);
  - per sensitive column, `min_l` (exact below 10 distinct values) and the classes with one
    value.
- [x] The report is computed on the output, after generalisation and suppression. It claims
  nothing.
- [x] `generalise`: `date = year|month`, `prefix = n`, `bin = w` with `bottom`/`top`
  coding. A value that does not fit stops the run, and the message never includes the
  value.
- [x] `require_min_k`: an optional gate that stops the run.
- Not built: automatic suppression of small classes. The gate tells the releaser to
  generalise further; dropping rows silently would change the dataset behind their back.

## v0.3.0: re-release chains — **Delivered 2026-11-08**

- [x] `deident history <dir>...` verifies that:
  - every release verifies (files optional with `--records-only`);
  - the releases are of one dataset to one recipient;
  - there is exactly one root;
  - every `parents` entry is the record hash of a release in the set, released earlier.
- [x] `deident run --parent <dir>`: the earlier release's record hash becomes a parent. A
  release of another dataset is refused.
- [x] Pseudonyms stay stable across re-releases to the same recipient (tested), so a delta
  after a deletion cycle replaces rows.
- Not built: diff records (rows removed since the parent). They need row identity, which a
  pseudonymised key column gives, and their format depends on ADR-0005.

## v0.4.0: Parquet — **Delivered 2026-11-08**

- [x] Parquet input and output through the `[parquet]` extra (pyarrow, streamed in batches).
- [x] Supported column types: strings, integers, floats, booleans, dates and timestamps.
  Anything else is refused.
- [x] Kept columns keep their type, and changed columns become strings.
- [x] The output is reproducible for the same pyarrow version, which is recorded in `tools`.

## v0.5.0: review hardening — **Delivered 2026-11-08**

- [x] All seven findings of the second review are fixed, each with a regression test. See
  CHANGELOG.
- [x] Draft schema: one `entities` key per column, and `risk.min_l_cap`.
- Not taken: nesting the generalise options into a sub-table, which the review suggested.
  The flat form reads better in a policy and the validation is already strict. Revisit if
  more transforms arrive.

## v0.6.0: California DROP lists — **Delivered 2026-11-08**

- `format = "ca-drop"` with `drop-email` and `drop-phone` standardisation, tested against
  the official CalPrivacy vectors (ADR-0006).
- Not yet: the composite NDZ and NameVIN lists, and the `Removed` file.

## v0.7.0: public contract — **Delivered 2026-11-08**

- `docs/SPEC.md`, `SEMVER.md`, `docs/KEYS.md`, `docs/THREAT-MODEL.md`.
- A committed, signed sample release, verified in CI.
- `verify --json` as `verify-result@1`; check names and exit codes frozen by tests.
- Detector id `presidio-regex-pii/1` (ADR-0009).

## Later versions (not scheduled)

- NLP-mode detection: names and locations.
- Recipient-risk statement (ADR-0007, under legal review).
- Shared PII detector package used by x402, `pai` and deident (ADR-0003, decided).
- Data Provenance Standards export.
- Multi-file releases and Merkle hashing.
- A `pai` ledger hook.
- An `iga` gate item "verified dataset-release present".
- arch-translucency training-run parents.
- A mapping note to the GPAI training-content summary template.

## v1.0.0: stable

- [ ] Frozen `dataset-release@1` schema with a compatibility policy.
- [ ] Threat model, and an external review of the cryptographic construction.
- [ ] Standalone verifier, documented for lab procurement teams.
- [ ] OpenSSF Best Practices silver; Scorecard 7.5+.

## Explicitly out of scope

- Watermarking or fingerprinting of datasets. These are strippable. The record binds the files
  by hash instead.
- Synthetic data generation, and differential privacy applied to the release itself. DP
  applies at training time via `pai`.
- Any statement that a dataset is "anonymous", and any HIPAA Expert Determination. PRESIDIO
  is not an expert of record.
- Hosted processing of customer datasets, in any form.
- Non-English NER, images, audio and video.
- Releases whose rights chain cannot be documented. The toolset records provenance; it does
  not clean it.

## Later — under evaluation

- A shared `presidio-hardened-pii` core (see the Split section).
- Locale packs for the regex detectors (EU national IDs, VAT numbers, German IBAN context).
- Implementation note for the OASIS DPS TC and the MLCommons Croissant RAI group.

## Version Release Checklist

At every release, before tagging: update this file (close delivered items with "Delivered"
and the date), the README roadmap and the `SECURITY.md` supported-versions table; then sign
the tag with the `presidio-v` release key.
