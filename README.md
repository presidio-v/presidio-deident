# presidio-deident

[![CI](https://github.com/presidio-v/presidio-deident/actions/workflows/ci.yml/badge.svg)](https://github.com/presidio-v/presidio-deident/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/presidio-v/presidio-deident/badge)](https://scorecard.dev/viewer/?uri=github.com/presidio-v/presidio-deident)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16454/badge)](https://www.bestpractices.dev/projects/16454)
[![PyPI](https://img.shields.io/pypi/v/presidio-deident.svg)](https://pypi.org/project/presidio-deident/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

De-identify a dataset before you license it to an AI developer, and sign a **release
record** that the buyer verifies offline.

The release record states what was removed, what remained, which opt-out and deletion
lists were applied, the sources and rights you declare, and the recipient. It carries
counts and hashes and never cell values. The record **documents**: it never states that
the output is anonymous. Whether data is personal for a given recipient is a legal
question for you and your counsel.

It runs where the data is. There is no hosted mode and no network access during a run.

**Status: alpha (v0.7.0).** The record format is `dataset-release@1`; see
[`docs/SPEC.md`](docs/SPEC.md) and the compatibility rules in [`SEMVER.md`](SEMVER.md). The
requirements and version plan are in [`PRESIDIO-REQ.md`](PRESIDIO-REQ.md), and decisions in
[`docs/adr/`](docs/adr/).

## Install

```bash
pip install presidio-deident        # Python 3.11+; depends on presidio-evidence and cryptography
```

The buyer installs the same package to verify. PII detection is built in and has no
NLP models or other heavy dependencies.

## Releaser: five commands

```bash
deident inspect tickets.csv                      # columns, missing values, PII types (counts only)
deident policy-init tickets.csv --out policy.toml
#   edit policy.toml: recipient, signer, rights, and review every column's action
deident keygen --signer acme-data-release --sign-key sign.key --pseudonym-key pseudo.key > trust.json
deident run --policy policy.toml --input tickets.csv --out release/ \
            --sign-key sign.key --pseudonym-key pseudo.key
deident verify release/ --trust trust.json       # what the buyer will run
```

Send the buyer the `release/` directory and `trust.json`, the public key. Never send the
keys. Keep the policy file: the record carries its SHA-256.

## Buyer: one command

Try it on the signed sample release in this repository (synthetic data):

```bash
pip install presidio-deident
git clone https://github.com/presidio-v/presidio-deident && cd presidio-deident
deident verify examples/sample-release --trust examples/sample-trust.json
```

On a release you received:

```bash
deident verify release/ --trust trust.json       # exit 0 only if every check passes
deident verify release/ --trust trust.json --json
```

Verify checks four things:
- the Ed25519 signature, from a signer in your trust store, bound to the framework
  `dataset-release` and to this dataset id (presidio-evidence `evidence-ref@3`);
- that the signature covers this exact record;
- that the row counts add up;
- that every data file is present, is not a symlink, and matches its SHA-256 and size.

The record says what was done. It does not say the result is anonymised. What it does and
does not prove: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

Exit codes for every command: `0` verified or done, `1` verification failed, `2` the command
could not run. The check names, the `--json` result (`verify-result@1`) and the record format
are specified in [`docs/SPEC.md`](docs/SPEC.md), so a lab can script against them or write its
own verifier. Keys and rotation: [`docs/KEYS.md`](docs/KEYS.md).

## The policy

```toml
[release]
dataset_id = "tickets-2026"
recipient = "lab-example"
signer = "acme-data-release"
released_at = "2026-11-08T00:00:00Z"   # optional; fixes the record for a reproducible run

[[release.rights]]
source = "Acme support system export, October 2026"
basis = "Customer terms section 7: licence for AI training"
reference = "contract 2026-114"

[columns]                              # every input column, or the run stops
ticket_id = { action = "pseudonymise" }
email = { action = "drop" }
country = { action = "keep" }
body = { action = "scrub_text" }

[[suppression]]                        # rows whose value is on the list are removed
name = "opt-out-2026-11"
file = "optout.txt"
column = "email"
format = "plain"                       # or "sha256": entries are hex SHA-256 of the normalised value
normalise = ["strip", "lower"]
as_of = "2026-11-01"
```

**California DROP lists.** Extract the deletion-list CSVs from the DROP download ZIP and name
one per suppression entry with `format = "ca-drop"` and the matching DROP standardisation:

```toml
[[suppression]]
name = "drop-email-2026-11"
file = "20261101_4821_Email.csv"       # header Id,Hash; Hash is SHA-256, Base64
column = "email"
format = "ca-drop"
normalise = ["drop-email"]             # or ["drop-phone"] for the Phone list
as_of = "2026-11-01"
```

`drop-email` removes whitespace and lowercases; `drop-phone` keeps the last 10 ASCII digits.
Both are tested against the official CalPrivacy vectors. The composite NDZ and NameVIN lists
and the `Removed` file are not supported yet.

| Action | Effect |
|---|---|
| `drop` | The column is not in the output. |
| `keep` | Unchanged. Scanned for PII: a hit stops the run unless the column has a `justification`, and then the counts are recorded. |
| `pseudonymise` | HMAC-SHA256 with your pseudonym key, derived per recipient (or per `pseudonym_domain`), truncated to 128 bits. Optional `normalise`. |
| `scrub_text` | Emails, phone numbers, US SSNs, card numbers, IBANs and IPv4 addresses are replaced by `<TYPE>`; counts are recorded. A value with no finding is written unchanged. |
| `generalise` | Coarsens a value: `date = "year"` or `"month"`; `prefix = 3` (postcodes); `bin = 10` with optional `bottom`/`top` coding (`"30-39"`, `"<20"`, `"80+"`). |

## Quasi-identifier risk

Columns that are harmless one by one can single a person out in combination (age, postcode,
visit date). Declare them, and the release record carries the equivalence-class
distribution of the **output**, computed after generalisation and suppression:

```toml
[risk]
quasi_identifiers = ["age", "postcode", "visit"]
sensitive = ["diagnosis"]       # optional: l-diversity
require_min_k = 5               # optional: stop the run if any class is smaller
```

The record states the number of classes, the smallest class (`min_k`), the number of
unique rows, the rows by class size, and per sensitive column the smallest number of
distinct values in a class (`min_l`). All of these are integers. It reports the
distribution and draws no conclusion from it. `deident risk file.csv --qi age,postcode`
gives the same report for any file, before you write a policy.

Detection is structural and regex-based, vendored from presidio-hardened-x402. It does not
find names, addresses or other free-text identifiers. Columns that may hold those should be
dropped or reviewed. `inspect` suggests actions from column names and detected types; the
suggestions are a starting point, not a decision.

## Re-releases

After the next deletion cycle, release again and name the earlier release as the parent:

```bash
deident run --policy policy.toml --input tickets.csv --out release-2026-12/ \
            --sign-key sign.key --pseudonym-key pseudo.key --parent release-2026-11/
deident history release-2026-11/ release-2026-12/ --trust trust.json
```

The new record lists the earlier record's hash in `parents`. Pseudonyms stay the same for
the same recipient, so the buyer can replace the old rows. `history` checks the whole
chain:
- every release verifies;
- all releases are of one dataset to one recipient;
- there is exactly one root release;
- every parent is in the set and was released earlier.

Add `--records-only` when the old data files are no longer kept.

## Formats

CSV (UTF-8, header required), JSONL (one flat object per line, scalar values) and Parquet
(`pip install 'presidio-deident[parquet]'`). The output keeps the input's format and
column order and is byte-for-byte reproducible for the same tool versions.

Parquet columns may be strings, integers, floats, booleans, dates or timestamps. Nested,
binary and decimal columns are refused. Kept columns keep their type; columns the policy
changes become strings. Dates and timestamps can be generalised.

## Roadmap

| Version | Scope | Status |
|---|---|---|
| v0.1.0 | Column policy, hashed suppression lists, signed `dataset-release@1` record, offline verify, Croissant pointer | built |
| v0.2.0 | Quasi-identifier risk report, generalisation, `require_min_k` gate | built |
| v0.3.0 | Re-release chains: `run --parent`, `history` | built |
| v0.4.0 | Parquet input and output (`[parquet]` extra) | built |
| v0.5.0 | Verify hardening from the second review; one `entities` key per column | built |
| v0.6.0 | California DROP email and phone deletion lists (`format = "ca-drop"`) | built |
| v0.7.0 | Public contract: SPEC, `verify-result@1`, signed sample release, threat model, key guidance | built |
| v1.0.0 | Frozen schema, external review, OpenSSF silver | planned |

**Next 12 months (to November 2027),** in priority order; dates follow design partners:

- First real release with a design partner; what it teaches becomes `dataset-release@2`, with
  `@1` still verified (ADR-0009).
- The record schema moves to presidio-evidence after that release (ADR-0004).
- The detector moves to a shared, standard-library-only PII package (ADR-0003).
- California DROP composite lists (name + date of birth + ZIP, name + VIN) when a releaser needs
  them (ADR-0006).
- A recipient-risk statement, only once its wording has passed legal review (ADR-0007).
- An external security review and OpenSSF silver, then 1.0.

Full detail is in [`PRESIDIO-REQ.md`](PRESIDIO-REQ.md).

## Contributing and security

Issues and pull requests are welcome on
[GitHub](https://github.com/presidio-v/presidio-deident/issues); see
[CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## License

MIT.
