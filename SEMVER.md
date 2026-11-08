# Stability and compatibility

For labs that script `deident verify`, and for anyone writing their own verifier.

## What is public

- **The record format** `presidio-deident/dataset-release@1` and the envelope rules in
  [`docs/SPEC.md`](docs/SPEC.md), with the schema `schemas/dataset-release.v1.json`.
- **The verifier CLI:** `verify` and `history`, their options, and the exit codes for every
  command (`0` verified or done, `1` verification failed, `2` the command could not run).
  The releaser commands (`run`, `policy-init`, `inspect`, `risk`, `keygen`, `croissant`)
  follow ordinary semver: additions in minor releases, removals announced one minor ahead.
- **`verify --json`:** the result format `presidio-deident/verify-result@1` and its keys.
- **Check names and outcomes:** the strings `verify` prints for each check
  (`docs/SPEC.md` section 4), and what each check accepts. The order of checks is not part of
  the contract: key on names.
- **The detector id** recorded in every release, `presidio-regex-pii/1`.

The Python modules are not a public API yet; use the CLI.

## Rules while the version is 0.x

- **A record that verifies keeps verifying.** A later 0.x verifier accepts every
  `dataset-release@1` record an earlier one accepted, unless the earlier acceptance was a
  security defect. Such a change ships as a patch release with an advisory.
- **Additive changes stay `@1`.** A new optional record key, a new check that existing records
  pass, a new `--json` key or a new subcommand is a minor release.
- **Anything that changes signed content or check meaning is a new format.** A renamed or
  removed record key, a changed hash or signature input, or a check that existing records
  would fail becomes `dataset-release@2`, verified side by side with `@1`. The same holds for
  `verify-result@2` and for the detector id (`presidio-regex-pii/2` when its matches change).
- **`verify` refuses a schema it does not know.** It never guesses.
- **Patch releases** (0.x.Y) fix bugs and security defects only.

`@1` is final from the first public release. What the first real releases teach becomes
`@2`, never an edit to `@1`.

## How long records verify

- **Every format verifies for the life of the project.** When `@2` exists, `@1` records keep
  verifying in every later version; there is no window after which a format is dropped.
- **Verification needs nothing from us:** no licence, no account, no server. The verifier and
  its test vectors are open source.
- **Test vectors** ship inside the package (`presidio_deident/vectors/`): releases that must
  verify and releases that must fail, each with the checks that must fail. They are
  append-only: a published vector is never edited or removed.

## Pinning

Pin `presidio-deident` to a minor version in a verification pipeline, and verify the committed
sample (`deident verify examples/sample-release --trust examples/sample-trust.json`) after
every upgrade.
