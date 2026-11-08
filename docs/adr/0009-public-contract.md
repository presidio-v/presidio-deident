# ADR-0009: The public contract at 0.x

**Status:** Accepted (2026-11-08).

## Context

Once the repository is public, three things change. Labs will put `deident verify` in scripts
and act on its exit code and `--json` output. Third parties may write their own verifier from
`docs/SPEC.md`, which is written to make that possible. And every release record a lab files
is long-lived evidence, signed with the **releaser's** key: we cannot re-sign or "fix" it, and
the releaser may no longer be able to either. If a later verifier rejects a record an earlier
one accepted, that evidence is dead. The contract exists so that a filed record is never
orphaned.

presidio-evidence already follows this rule (its ADR-0001 D5): a published format is frozen,
a change becomes a new major that is verified side by side, test vectors are append-only, and
no major is ever dropped. deident should say the same thing.

## Decision 1: what is frozen at 0.x

| Surface | Freezing means | Cost of freezing | Cost of not freezing | Recommendation |
|---|---|---|---|---|
| **Record format `dataset-release@1`** | No key renamed or removed; no change to what is hashed or signed. New optional keys allowed. | A design mistake lives on in `@1`; the fix is `@2`, verified alongside. | Filed records stop verifying, and nobody can re-sign them. | **Freeze** |
| **Exit codes 0 / 1 / 2** | Meanings never change. | None. | Every lab script breaks. | **Freeze** |
| **`--json` keys (`verify-result@1`)** | The eight keys and the `check` / `ok` / `detail` triple stay; new keys may be added in a minor release. | None worth naming. | Parsers break silently. | **Freeze present keys; additions allowed** |
| **Check names** | The spelling of every check never changes; a rename is `verify-result@2`. | A clumsy name is permanent. | Scripts that look for a check by name break. | **Freeze** |
| **Check outcomes** | No check gets stricter for existing records, except to fix a security defect (with an advisory). | Tightening a check means `@2`. | A good record fails later. This matters most. | **Freeze** |
| **Check order** | Position in the list never changes. | New checks can only be appended. | Nothing real: `ok` and the names carry the meaning. | **Do not freeze.** Labs key on names, not position. |
| **`verify` and `history` CLI** | No removals or changes of meaning. | Minimal. | Scripts break. | **Freeze** |
| **Producer CLI (`run`, `policy-init`, `inspect`, `risk`, `keygen`, `croissant`)** | Ordinary semver: additions in minors, removals announced one minor ahead. | Slower change to the releaser workflow. | Little; these run interactively. | **Ordinary semver** |
| **Sample release** | `examples/sample-release/` verifies on every future version, also after `@2` exists. | One committed directory. | We lose the proof that old records still verify. | **Freeze, and extend (Decision 3)** |
| **Python modules** | Not public; the CLI is the interface (as `SEMVER.md` says). | None now. | Free refactoring; importers were warned. | **Do not freeze.** Revisit at 1.0 |

**"Draft" versus "keeps verifying".** `docs/SPEC.md` calls `@1` a draft until 1.0, while
`SEMVER.md` promises that every accepted record stays accepted. Both hold only if "draft"
means "may be superseded by `@2`", never "may be edited". The word invites labs to wait and
invites us to tinker. **Recommendation:** drop "draft". `@1` is the current format from the
first public release; before 1.0 a `@2` may appear, and `@1` records keep verifying. This also
governs ADR-0004: when the schema moves to presidio-evidence after the first real release, it
moves as `@1` unchanged, and anything learnt from that release becomes `@2`.


## Decision 2: the detector id

Every record carries `detector: {name, entities}`. A lab reads it as "which pattern set
scrubbed this text". `verify` does not check it; it is a recorded statement, like the tool
version.

| Option | What a lab sees | When the shared package lands or the patterns change |
|---|---|---|
| `x402-regex (vendored)` (until v0.6) | A payments product named in a privacy record | Wrong the day the copy is removed |
| **`presidio-regex-pii/1`** (built) | A neutral name for the pattern set; `/1` is its revision | Unchanged if the shared package matches identically (the parity test proves it); the first change in matches makes it `/2`; old records still say `/1`, which stays true |
| `presidio-pii/regex@1` | A package-style name | The package does not exist yet and its name is not settled; a guessed name in filed records is wrong forever. `@1` also looks like a format major, which follows other rules |
| Add a pattern-set hash | More precise reproducibility | As a new required key it is a format change; as an optional key (`patterns_sha256`) it can be added later under `@1` if a lab asks |

**Recommendation:** keep `presidio-regex-pii/1`. The id belongs to the pattern set, not to the
package that hosts it, and moves to the shared package unchanged. Bump the suffix whenever the
matches differ on the parity inputs.

## Decision 3: lifetime, migration, test vectors

- **How long old formats verify.** **Recommendation:** every `dataset-release@N` verifies for
  the life of the project, with no window after which it is dropped, as in presidio-evidence.
  Records outlive licences and projects; the open-source verifier is what stands between a lab
  and evidence nobody can check. Cost: a few hundred lines per major, kept.
- **Verification needs nothing from us.** State in `SEMVER.md`: verifying never needs a
  licence, an account or a server.
- **Test vectors.** Publish `vectors/` as presidio-evidence does: the signed sample (must
  verify) plus negative vectors (a tampered file, an untrusted signer, an envelope field that
  does not match, a float in the record) with an `expectations.json`; append-only; shipped in
  the wheel so `pip install` is enough. **Recommendation:** yes, before any third-party
  verifier exists, in v0.7.x or v0.8.

## Decision

All six recommendations are accepted: the record `@1`, exit codes, `--json` keys, check names
and outcomes, the `verify` / `history` CLI and the sample release are frozen; check order and
the Python modules are not; `@1` is final, superseded only by `@2`; the detector id is
`presidio-regex-pii/1`; every format verifies for the life of the project; positive and
negative test vectors ship in the package.
