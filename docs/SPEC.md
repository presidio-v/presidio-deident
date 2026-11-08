# `dataset-release@1`: the release record and how to verify it

Status: the current format from the first public release. A later `@2` may supersede it;
`@1` records keep verifying. Compatibility rules: [`SEMVER.md`](../SEMVER.md).
Machine-readable schema: [`schemas/dataset-release.v1.json`](../schemas/dataset-release.v1.json).
A worked, signed example: [`examples/sample-release/`](../examples/sample-release/) with the trust
store [`examples/sample-trust.json`](../examples/sample-trust.json).

Test vectors (releases that must verify and releases that must fail, with the checks that
must fail) ship in the package under `presidio_deident/vectors/`.

This document is enough to write an independent verifier. `deident verify` is the reference
implementation (`src/presidio_deident/verify.py`).

## 1. What a release is

A release is one directory:

| File | What it is |
|---|---|
| the data file(s) | the released dataset, for example `tickets.csv` |
| `release.json` | the **record**: plain JSON, counts and hashes, never cell values |
| `release.evidence.json` | an `evidence-ref@3` envelope from [presidio-evidence](https://github.com/presidio-v/presidio-evidence) that signs the record |

The record documents what was done to the data. It does not state that the result is
anonymous, compliant or fit for a purpose. See [`THREAT-MODEL.md`](THREAT-MODEL.md).

## 2. The record

A JSON object. Required keys (the schema allows no others):

| Key | Type | Meaning |
|---|---|---|
| `schema` | string | exactly `presidio-deident/dataset-release@1` |
| `release_id` | string | `"<dataset_id>@<released_at>"` |
| `dataset_id` | identifier | the releaser's name for the dataset |
| `recipient` | identifier | who the release is for |
| `signer` | identifier | the signer id in the buyer's trust store |
| `released_at` | timestamp | `YYYY-MM-DDTHH:MM:SSZ`, UTC |
| `policy_sha256` | hex64 | SHA-256 of the policy file's bytes (the releaser keeps the file) |
| `sources` | list | each input file: `name`, `sha256`, `bytes`, `rows` |
| `outputs` | list | each released file: `name`, `sha256`, `bytes`, `rows` |
| `rows` | object | `in`, `suppressed`, `out` (integers) |
| `columns` | list | per input column: `name`, `action`, `changed`, `missing`; `justification` where the policy gives one; `entities` (counts by PII type) for `scrub_text`, and for `keep` when `residual_scan` is true; `normalise` / `generalise` where used |
| `suppression` | list | per list: `name`, `column`, `format`, `normalise`, `as_of`, `sha256` of the list file, `entries`, `rows_matched` |
| `detector` | object | `name` (`presidio-regex-pii/1`) and the `entities` it looks for |
| `residual_scan` | bool | whether kept columns were scanned for PII |
| `rights` | list | `source`, `basis`, `reference`, as declared by the releaser |
| `tools` | object | versions of `presidio-deident`, `presidio-evidence` (and `pyarrow` for Parquet) |

Optional: `pseudonyms` (present when a column is pseudonymised: `scheme`
`hmac-sha256-128/v1` and `domain`, never the key), `parents` (list of record hashes of earlier releases of the same dataset to the same
recipient, present only when non-empty) and `risk`: `quasi_identifiers`, `rows`, `classes`,
`min_k`, `unique_rows`, `rows_by_class_size`, optionally `require_min_k`, and for sensitive
columns `sensitive.<column>.min_l` and `.classes_with_one_value` with the cap `min_l_cap`.

*Identifier*: `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`. *hex64*: 64 lowercase hex characters.
All numbers are integers; the record contains no floats.

### Record hash

`record_hash = SHA-256( canonical(record) )`, lowercase hex, where `canonical` is
presidio-evidence's canonical JSON: keys sorted, separators `,` and `:`, UTF-8 without ASCII
escaping, floats and NaN refused. A release's `parents` and a Croissant file refer to it by this
hash.

## 3. The envelope

`release.evidence.json` is an `evidence-ref@3` envelope with exactly these keys:

```json
{
  "schema": "presidio-hardened/evidence-ref@3",
  "source": "presidio-deident",
  "source_version": "<tools.presidio-deident>",
  "generated_at": "<released_at>",
  "evidence": [ {
    "content_hash": "<record_hash>",
    "framework": "dataset-release",
    "item_id": "<dataset_id>",
    "signer": "<signer>",
    "ledger_ref": "release.json",
    "claimed_at": "<released_at>",
    "source": "presidio-deident",
    "source_version": "<tools.presidio-deident>",
    "signature": "<hex Ed25519 signature>"
  } ]
}
```

The signature is Ed25519 over presidio-evidence's `@3` message,
`canonical({assurance_tier, content_hash, framework, item_id, signer})`, with
`assurance_tier = "attested"` when absent (presidio-evidence ADR-0004). **Only those fields are
signed.** `claimed_at`, `source`, `source_version`, `ledger_ref` and `generated_at` are not, so a
verifier must require them to repeat the signed record (check 12 below).

## 4. Verification

Inputs: the release directory and a trust store (`{signer: {"alg": "ed25519", "public_key":
hex or [hex, ...]}}`, presidio-evidence `trust-store@1`; `deident keygen` writes Ed25519
entries, and presidio-evidence also accepts `hmac-sha256` entries).

`deident verify` does not validate the record against the JSON Schema. The schema describes
what `deident run` writes; the checks below are what a release must pass. A verifier may
apply the schema in addition, and then also refuses records with unknown keys. Every check below must pass; any
failure means the release does not verify. The check names are the strings `deident verify`
prints and are stable (see `SEMVER.md`).

| # | Check | Passes when |
|---|---|---|
| 1 | `record schema` | `schema` is `presidio-deident/dataset-release@1` |
| 2–4 | `record dataset_id / recipient / signer is an identifier` | each matches the identifier pattern |
| 5 | `record released_at is a UTC timestamp` | matches `YYYY-MM-DDTHH:MM:SSZ` |
| 6 | `exactly one signed ref` | the envelope parses and holds exactly one ref |
| 7 | `signature (evidence-ref@3, trusted signer)` | the ref is `@3` for framework `dataset-release`, its signer is in the trust store, and one of its keys verifies the signature |
| 8 | `ref signs this record` | `content_hash` equals the record hash |
| 9 | `ref names this dataset` | `item_id` equals `dataset_id` |
| 10 | `ref signer is the record signer` | `signer` matches |
| 11 | `ref points at release.json` | `ledger_ref` is `release.json` |
| 12 | `unsigned envelope fields match the record` | `claimed_at` and `generated_at` equal `released_at`; both `source` fields are `presidio-deident`; both `source_version` fields equal `tools.presidio-deident`; the envelope and the ref have exactly the keys shown in section 3 |
| 13 | `row counts add up` | `in = suppressed + out`, and the outputs' `rows` sum to `out` |
| 14 | `parents are record hashes` | `parents`, if present, is a non-empty list of hex64 |
| 15 | `release id names the dataset and time` | `release_id` is `dataset_id@released_at` |
| 16 | `record lists output files` | `outputs` is a non-empty list |
| per file | `output file name is plain`, `<f> listed once`, `<f> present`, `<f> sha256`, `<f> size` | a plain name (no path, not a release file), listed once, a regular file (not a symlink) in the directory, whose SHA-256 and byte size match |

Checks that stop verification early, each a failure: `release files readable` (the record or
envelope cannot be read or is not a bounded JSON object), `record canonical` (the record
cannot be canonically encoded, for example it holds a float), `envelope well-formed`, and
`<f> readable` for a listed file that cannot be read.

Files in the directory that the record does not list are reported, not failed.

A second opinion without deident: `presidio-evidence verify --trust trust.json
--require-subject-binding dataset-release release.evidence.json` checks the signature (checks
6–7) with presidio-evidence alone. It does not check the record or the files.

### A chain of releases

`deident history DIR...` verifies re-releases of one dataset to one recipient (for example
after each deletion cycle): every release verifies on its own; all share `dataset_id` and
`recipient`; there is exactly one release without `parents`; every parent is the record hash
of a release in the set and was released earlier.

## 5. `deident verify --json`

Result format `presidio-deident/verify-result@1`:

```json
{
  "result": "presidio-deident/verify-result@1",
  "ok": true,
  "schema": "presidio-deident/dataset-release@1",
  "release_id": "tickets-2026@2026-11-08T00:00:00Z",
  "record_hash": "<hex64>",
  "checks": [ { "check": "record schema", "ok": true, "detail": "..." } ],
  "extra_files": [],
  "verifier": { "presidio-deident": "0.7.0", "presidio-evidence": "0.5.1" }
}
```

`schema` and `release_id` are `null` unless `ok` is true; `record_hash` is `null` when the
record cannot be read or canonically encoded. Exit codes for every command: `0`
verified or done, `1` verification failed, `2` the command could not run (bad arguments,
unreadable trust store, a policy error).

## 6. Pointing to a release from dataset metadata

`deident croissant` writes a minimal [Croissant](https://mlcommons.org/croissant/) file whose
`identifier` is `dataset-release:sha256:<record_hash>`. In a Hugging Face dataset card, the same
identifier can go in the front matter:

```yaml
dataset_release:
  record: dataset-release:sha256:<record_hash>
  verify: pip install presidio-deident && deident verify <dir> --trust trust.json
```
