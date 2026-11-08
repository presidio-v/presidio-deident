# ADR-0004: Release layout, and where `dataset-release@1` lives

**Status:** Accepted (2026-11-08).

**Layout:** a release directory holds the data file(s); `release.json`, the record (counts
and hashes); and `release.evidence.json`, a presidio-evidence `evidence-ref@3` envelope with
`framework = "dataset-release"`, `item_id = dataset_id`, `content_hash = content_hash(record)`
and `ledger_ref = "release.json"`. The record is what later releases (`parents`) and Croissant
files refer to by hash. Any presidio-evidence consumer can check the signature, for example
`presidio-evidence verify --require-subject-binding dataset-release`.

**Unsigned envelope fields.** `evidence-ref@3` signs `content_hash`, `signer`, `framework`,
`item_id` and the tier. `claimed_at`, `source`, `source_version`, `ledger_ref` and
`generated_at` are not signed. deident's verify therefore requires each of them to repeat the
signed record and allows no other keys. A future evidence-ref format should sign the release
date.

**Where the schema lives:**

| | Option | For | Against |
|---|---|---|---|
| A | In deident: `schemas/dataset-release.v1.json`; `deident verify` re-hashes files | Changes do not need a presidio-evidence release | A lab installs deident to verify (a light install) |
| B | In presidio-evidence, with a file-hashing verifier there | One verifier for the whole family | Ties the record to evidence's release cycle before it has met a real release |

**Decision:** A until a design partner has produced one real release, then B. The format moves
as `@1` unchanged; anything learnt from that release becomes `@2` (ADR-0009).
