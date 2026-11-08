# Architecture

This document describes the high-level design of `presidio-deident`: its
components, how data flows through them, and the trust boundaries the project is
built to enforce. For the security requirements and threat model that motivate
this design, see [SECURITY.md](SECURITY.md) and the assurance case in
[ASSURANCE.md](ASSURANCE.md).

## Overview

`presidio-deident` is a command-line tool and Python package with two users. A **releaser**
(a company or data broker) runs it in its own environment to de-identify a tabular dataset
under a written policy and to sign a release record. A **buyer** (typically an AI lab) runs
it offline to verify that record against the files it received. It is stateless between
runs, makes **no network calls**, and has no hosted mode. Its design stance: document what was
done, in counts and hashes only, and fail closed on anything it cannot do faithfully.

## Components

| Component | Responsibility |
|---|---|
| `policy.py` | Parse and validate the TOML policy (fail closed on unknown keys, missing columns, PII in free text) |
| `tables.py` | Read and write CSV, JSONL and Parquet; refuse input it cannot write back faithfully |
| `_detect.py` | Structural PII detector (`presidio-regex-pii/1`): normalisation, decoding, six patterns |
| `generalise.py` | Coarsen dates, prefixes and integer bins |
| `release.py` | The run: transforms, suppression lists, pseudonyms, residual scan, atomic output, record, signing |
| `risk.py` | Quasi-identifier equivalence classes (`min_k`, uniqueness, `min_l`) as integers |
| `verify.py` | Offline verification of one release and of a re-release chain |
| `inspect.py` | Column profile and suggested actions, counts only |
| `croissant.py` | A minimal Croissant pointer to a verified release |
| `cli.py` | The `deident` command; exit codes 0/1/2 |

Signing, canonical hashing and trust stores come from `presidio-evidence`; nothing
cryptographic is implemented here.

## Data / processing flow

**Run:** load and validate the policy → open the input → for each row: apply suppression lists
(drop the row on a match), then each column's action (drop, keep with residual scan,
pseudonymise, scrub_text, generalise) → write to `<out>.partial` (files `0600`, directory
`0700`) → compute the risk report and apply the `require_min_k` gate → hash every file →
build the record → sign it as an `evidence-ref@3` envelope → rename `<out>.partial` to
`<out>`. Any error at any step stops the run and leaves no release directory. The order
"suppress, then transform" is part of the contract: suppression matches the original values.

**Verify:** read the record and the envelope (size-bounded) → check the record's fields →
verify the signature against the trust store → bind the unsigned envelope fields to the
signed record → check the row arithmetic → hash every listed file. Every check is evaluated
and reported; the release verifies only if all pass. See `docs/SPEC.md` section 4.

## Trust boundaries

1. **Input data → the run.** The dataset is untrusted and may be malformed. Readers refuse what
   they cannot round-trip (bad UTF-8, lone surrogates, NaN, nested values, malformed CSV).
   Errors name the row and column, never the value.
2. **Policy and lists → the run.** Written by the releaser, but validated strictly; free text
   that goes into the record is checked for PII.
3. **The run → the release directory.** The only data leaving the run. The record and envelope
   carry counts and hashes only; tests assert that no input value appears in them.
4. **Keys.** The signing and pseudonym keys stay in the releaser's environment, as `0600`
   files; nothing outputs them.
5. **Release directory → verify.** Everything the buyer receives is untrusted: file names are
   plain basenames, symlinks are refused, JSON is size-bounded, and only the trust store
   (obtained out of band) is trusted.
