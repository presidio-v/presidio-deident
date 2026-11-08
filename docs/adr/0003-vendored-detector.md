# ADR-0003: A vendored PII detector now, a shared package later

**Status:** Accepted (2026-11-08).

**Context:** the structural PII detector (six identifier types, with normalisation and
decoding of percent-encoding, HTML references and Unicode format characters) comes from
presidio-hardened-x402's `PIIFilter`. Depending on that package would pull in
presidio-analyzer, spaCy and a payments stack, which is too heavy for a lab that installs
deident only to verify.

**Options:**

| | Option | For | Against |
|---|---|---|---|
| A | Depend on `presidio-hardened-x402` | One copy of the code | Heavy install; unrelated warnings; x402's release cadence drives deident |
| B | Vendor the patterns into `_detect.py` | No extra dependency; one small file | Two copies; fixes must be ported |
| C | A shared, standard-library-only PII package used by x402, presidio-hardened-ai and deident | One copy, light | A new package and release |

**Decision:** C is the target. Until the shared package exists, deident keeps the vendored copy
(B). `tests/test_detect.py::test_parity_with_x402` checks that the copy and the installed x402
agree on a set of tricky inputs (the `[parity]` extra, run in CI). Records name the pattern
set, not its host package: `presidio-regex-pii/1` (ADR-0009).

**History:** a review of the copy found the email pattern quadratic on a long run of
local-part characters without `@`. deident's copy anchored the match with a lookbehind; the
claim that matches were unchanged was wrong. The anchored pattern missed an address that
directly follows another through a local-part character (`a@b.cc+victim@example.com`), a
redaction bypass that differential testing against the original regex found. Since 0.7.1 an
explicit scanner returns exactly the original regex's matches in linear time, and the detector
id is `presidio-regex-pii/2`.
