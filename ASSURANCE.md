# Security Assurance Case

This document is the assurance case for `presidio-deident`: an explicit argument
for why the project's security requirements are met. It has four parts, as
required by the OpenSSF Best Practices silver criterion `assurance_case`:

1. the threat model,
2. the trust boundaries,
3. the argument that secure design principles are applied, and
4. the argument that common implementation weaknesses are countered.

It is a summary that links to the authoritative detail in
[`SECURITY.md`](SECURITY.md) (controls, known limits, reporting) and
[`ARCHITECTURE.md`](ARCHITECTURE.md) (components, flow, boundaries) for
`presidio-v/presidio-deident`.

## 1. Threat model

The full statement of what a record proves and does not is in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). In short:

| Threat | Control |
|---|---|
| Released files swapped or edited | per-file SHA-256 and size in the signed record |
| Record edited after signing | Ed25519 signature over the canonical record hash (`evidence-ref@3`) |
| Unsigned envelope fields edited (dates, versions) | verify requires them to equal the signed record |
| A record presented for another dataset | `@3` subject binding to `dataset-release` and `dataset_id` |
| Path traversal or symlinks in a crafted release | plain basenames only; symlinks refused |
| Resource exhaustion on verify | size-bounded JSON, recursion guard; linear-time detector patterns |
| Input values leaking into evidence | counts and hashes only; tests assert no value appears in any output |
| A failed run mistaken for a release | atomic `<out>.partial` rename after signing |

Out of scope: the releaser's honesty (it holds the key and the code), the truth of the
source and the rights declarations, detector recall (structural patterns only), and whether
the output is personal data for a given recipient.

## 2. Trust boundaries

Same boundaries as [ARCHITECTURE.md](ARCHITECTURE.md#trust-boundaries): input data → run,
policy and lists → run, run → release directory, keys, release directory → verify. At each,
untrusted data is validated before use and the run or the check fails closed.

## 3. Secure design principles applied

- **Fail closed.** An unknown policy key, a column without a policy entry, a value that cannot be
  written faithfully, a leftover `.partial`: each stops the run. A release verifies only if every
  check passes; malformed input is a failed check, never a pass.
- **Least privilege and least data.** No network access, no hosted mode, and the record holds no
  values. Output files are `0600` in a `0700` directory.
- **Complete mediation.** Every listed file is re-hashed on every verify; nothing is cached.
- **Defense in depth.** The signature covers the record; the record covers the files; the
  unsigned envelope fields are bound to the record; history checks bind releases together.
- **Economy of mechanism.** Ed25519, SHA-256 and HMAC-SHA256 through `presidio-evidence` and
  `cryptography`; no bespoke cryptography. One base dependency.

## 4. Common implementation weaknesses countered

| Weakness class | How it is countered |
|---|---|
| Path traversal (CWE-22) | output names must be plain basenames and not the release files; symlinks refused |
| Uncontrolled resource consumption (CWE-400, CWE-1333) | size-bounded JSON; recursion errors caught; the email pattern anchored to stay linear |
| Improper input validation (CWE-20) | strict CSV/JSONL/Parquet readers; identifiers and timestamps matched in full |
| Information exposure (CWE-200, CWE-532) | errors and outputs name rows, columns and counts, never values |
| Insecure randomness (CWE-330) | keys from `secrets` / `cryptography`; `S311` allowed only in tests |
| Hard-coded secrets (CWE-798) | keys are files, never in code; `S105`/`S106` enforced outside tests |
| Integrity of data (CWE-345, CWE-354) | signature over the canonical record; per-file hashes |

Static analysis: CodeQL and OpenSSF Scorecard on pushes to `main` and on pull requests, ruff with the bandit-derived
`S` rules in CI, `pip-audit` for dependencies, and Atheris fuzzing of the readers and the
verifier. Two internal review passes were done during development (CHANGELOG 0.2.0 and 0.5.0);
there has been no external review or security audit yet.

## Conclusion

The threats above are each matched to a control; the controls sit at explicit
trust boundaries; the design follows fail-safe, least-privilege, complete-
mediation, defense-in-depth, and economy-of-mechanism principles; and the common
implementation weakness classes are countered by design and checked by automated
analysis. The project's stated security requirements are therefore met, subject
to the documented out-of-scope assumptions.
