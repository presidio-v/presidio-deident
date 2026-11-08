# Changelog

## [0.7.1] — unreleased

### Security

- **Redaction bypass in the email pattern.** From 0.2.0 to 0.7.0 the email pattern was
  anchored with a lookbehind to keep it linear. That missed an address that directly follows
  another one through a local-part character, so in `a@b.cc+victim@example.com` the second
  address was neither redacted by `scrub_text` nor counted by the residual scan. An explicit
  scanner now returns exactly the matches of the original regex, in linear time; a
  differential test checks this on random input.
- The detector id in new records is `presidio-regex-pii/2`. Records made with `/1` keep
  verifying.

## [0.7.0] — 2026-11-08

The first version prepared for publication: a public contract a lab can script against.

### Added

- `docs/SPEC.md`: the `dataset-release@1` record, the envelope, and the verification algorithm,
  enough to write an independent verifier. A test keeps its key table in step with the schema.
- `SEMVER.md`: what is public and how it may change; `docs/KEYS.md` (trust-store delivery,
  rotation, what is not supported); `docs/THREAT-MODEL.md` (what a record proves and does not).
- `examples/sample-release/` and `examples/sample-trust.json`: a signed release of the synthetic
  example, verified by a test as a compatibility vector.
- `verify --json` now carries `result` (`presidio-deident/verify-result@1`), `schema`,
  `release_id` (both `null` unless verified) and `verifier` versions. Check names are frozen by
  a test.
- A history test for signing-key rotation (two keys for one signer in the trust store).
- Test vectors in the package (`presidio_deident/vectors/`): one release that must verify and
  five that must fail (untrusted signer, tampered file, edited envelope, edited record, float
  in the record), each with the checks that must fail. Append-only (ADR-0009).

### Changed

- `dataset-release@1` is no longer called a draft: it is final from the first public
  release, and a change becomes `@2` while `@1` records keep verifying (ADR-0009).
- Check names are frozen; their order is not.
- **Record:** the detector is recorded as `presidio-regex-pii/1` instead of
  `x402-regex (vendored)`, a stable id that does not name where the code came from (ADR-0009).
- `keygen` makes the pseudonym key from 32 random bytes directly, not from an Ed25519 key
  generator.
- Package metadata: Alpha status and project URLs.

### Added (repository)

- The OpenSSF silver governance set: `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`,
  `CONTRIBUTING.md`, `ARCHITECTURE.md`, `ASSURANCE.md`, `allowed_signers`, CODEOWNERS,
  Dependabot, CodeQL and bandit, Scorecard, and a Trusted Publishing `publish.yml` with an SBOM
  and build provenance.

## [0.6.0] — 2026-11-08

### Added

- `format = "ca-drop"` for California DROP deletion lists: one DROP CSV (`Id,Hash`, SHA-256
  in Base64) per suppression entry. `normalise = ["drop-email"]` or `["drop-phone"]` applies
  DROP's standardisation. Tested against the official CalPrivacy vectors. A list with
  another header, such as the `Removed` file, is refused. Composite NDZ and NameVIN lists are
  not supported yet (ADR-0006).

### Changed

- Decisions recorded in ADR-0002 to ADR-0008.

## [0.5.0] — 2026-11-08

Second code review, at v0.3.1.

### Fixed

- `verify` now checks:
  - that `dataset_id`, `recipient` and `signer` are identifiers;
  - that `released_at` is a UTC timestamp (before, `history` ordered free text);
  - that row counts are integers, not booleans;
  - that each output file is listed once and is not named after the release files.
- An unreadable data file is a failed check, not a traceback.
- `history` and `croissant` no longer crash on a record without a valid recipient.
- `run --parent` refuses a release to another recipient.
- File-system errors on any command are reported as `error:` with exit code 2.
- `scrub_text` writes a value with no finding unchanged. Before, it wrote the
  Unicode-normalised form and counted it as changed.
- Generalised dates and integer bins accept ASCII digits only.

### Changed

- **Record (draft schema):** a kept column's residual findings now use the same
  `entities` key as `scrub_text`; the column's `action` tells them apart.
  `risk.min_l_cap` records the cap on `min_l`.
- A leftover `<out>.partial` is refused instead of deleted.
- `History` reuses `Verification`, and `REF_KEYS` comes from presidio-evidence.

## [0.4.0] — 2026-11-08

### Added

- Parquet input and output through the optional `[parquet]` extra (pyarrow):
  - streamed in batches;
  - kept columns keep their type, and changed columns become strings;
  - nested, binary and decimal columns are refused;
  - output is reproducible for the same pyarrow version, which the record names.
- `inspect`, `risk` and `run` share one table layer for all three formats.

## [0.3.1] — 2026-11-08

### Fixed

- `verify` now binds the envelope fields that `evidence-ref@3` does not sign (`claimed_at`,
  `source`, `source_version`, `generated_at`) to the signed record, and refuses extra keys.
  Before, an edited `claimed_at` still verified. Found by the new mutation tests.

### Added

- Seeded mutation tests for verify, the readers and the policy parser.
- Atheris harnesses (`fuzz/`) and a CI fuzz job.
- Checked by hand: the wheel installs into a fresh Python 3.11 venv with presidio-evidence
  and cryptography only, and the worked example runs and verifies.

## [0.3.0] — 2026-11-08

### Added

- `deident run --parent DIR`: the earlier release's record hash goes into `parents`. A release
  of another dataset is refused.
- `deident history DIR...`: verifies releases of one dataset to one recipient as a chain:
  - each release verifies;
  - there is one root;
  - every parent is in the set and was released earlier;
  - `--records-only` skips the old data files.

## [0.2.0] — 2026-11-08

### Added

- `generalise` action: dates to year or month, string prefixes, integer bins with bottom and
  top coding.
- `[risk]` policy section:
  - quasi-identifier equivalence classes over the output, recorded as integers (classes,
    `min_k`, unique rows, rows by class size, `min_l` per sensitive column);
  - an optional `require_min_k` gate that stops the run.
- `deident risk`: the same report for any CSV or JSONL file.

### Fixed (from the v0.1 code review)

- The email pattern was quadratic on long runs of local-part characters (40k characters:
  seconds; a 1 MB cell: hours). A lookbehind now anchors it at run starts; matches are
  unchanged. **The same pattern is in presidio-hardened-x402** (see ADR-0003).
- `verify` fails cleanly, without a traceback, on:
  - non-integer row counts;
  - deeply nested JSON;
  - a record without a matching `release_id`, which is now a verified check.
- `run` refuses input it cannot write faithfully, naming the line and field and never the
  value:
  - JSONL lone surrogates, `NaN`, `Infinity` and out-of-range numbers;
  - non-UTF-8 input.
- Identifiers, timestamps and `parents` are matched in full; a trailing newline no longer
  passes.
- `croissant` reports a bad trust store as an error (exit 2).

## [0.1.0] — 2026-11-08

### Added

- `deident inspect`: columns, missing values, detected PII types and suggested actions,
  counts only.
- `deident policy-init`: a TOML policy skeleton listing every column.
- `deident keygen`: an Ed25519 signing key and a pseudonym key, both `0600`, plus the trust
  store to hand to the buyer.
- `deident run`: the column actions `drop`, `keep` (with a residual PII scan),
  `pseudonymise` (HMAC-SHA256 per recipient) and `scrub_text`, plus suppression lists in
  plain or SHA-256 format. Writes the data file, `release.json` (the record) and
  `release.evidence.json` (an `evidence-ref@3` envelope).
- `deident verify`: offline, fail-closed checks of the signature, subject binding, record
  hash, row arithmetic and file hashes, with a `--json` output.
- `deident croissant`: a minimal Croissant file pointing at a verified release by its record
  hash.
- A structural PII detector vendored from presidio-hardened-x402 0.14.0, with a parity test.
- Draft JSON Schema `schemas/dataset-release.v1.json`.
