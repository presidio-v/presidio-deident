# ADR-0002: TOML policy, validated in code

**Status:** Accepted (2026-11-08).

**Decision:** the policy is TOML, read with the standard library's `tomllib` (no dependency)
and validated by hand-written, fail-closed code in `policy.py`:
- an unknown key, a wrong type or a missing column stops the run;
- `policy_sha256` in the record is the SHA-256 of the policy file's bytes, the file the
  releaser keeps. Hashing a parsed form would fail on TOML dates and floats.

**Why not YAML:** it adds a dependency, and its implicit typing (`no` → false, `2026-11-01`
→ date, `010` → 8) is a trap in a file whose job is to be exact.

**Consequence:** there is no machine-readable policy schema for editors. A JSON Schema can be
added later without changing the format.
