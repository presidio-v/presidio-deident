# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.7.x | yes |
| < 0.7 | no |

## Reporting a vulnerability

Do not open a public issue. Use a private advisory under "Security → Report a
vulnerability" on GitHub, or write to `security@presidio-group.eu`.

We acknowledge within five business days and aim to ship a fix within 30 days. Reporters
are credited in the advisory and in the `CHANGELOG.md` entry for the fix unless they ask not
to be.

## Security properties

- **No values in evidence.** The record, the envelope, CLI output and error messages carry
  column names, file names, counts and hashes, never cell values. Tests assert this for every
  output on synthetic fixtures.
- **Keys:**
  - The signing key and the pseudonym key are separate files, created `0600`, refused
    if they are group- or world-readable, and never written to any output.
  - Pseudonym keys are derived per recipient, so two releases to different recipients
    cannot be joined on their pseudonyms.
- **Fail-closed run:**
  - An input column without a policy entry, a policy column missing from the input,
    an unknown policy key, a non-text value under `scrub_text`, or detected PII in a kept
    column without a justification stops the run.
  - The run writes into `<out>.partial` and renames it only after signing, so a failed
    run leaves no release-like directory. A leftover `.partial` from an interrupted run
    is refused, never deleted.
  - Output files are `0600` in a `0700` directory.
- **Fail-closed verify:**
  - Output file names must be plain basenames, so a crafted record cannot point
    outside the release.
  - Symlinks are refused, and JSON files are size-bounded.
  - The signature must be `evidence-ref@3`, bound to `dataset-release` and to this
    dataset id.
- **Human-written text** (rights, justifications) is bounded to 512 characters and refused
  if the detector finds PII in it.
- **No network.** A run and a verify make no network calls. There is no telemetry.

## Known limits

- Detection is structural (regex): it does not find names, postal addresses or other
  free-text identifiers.
- A release record documents the actions taken. It is not an anonymisation opinion. Row and
  suppression counts across two releases to the same recipient allow differencing. See
  [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) and [`docs/KEYS.md`](docs/KEYS.md).
- Suppression lists in `sha256` format use unkeyed SHA-256, which is guessable for
  low-entropy values. See `docs/adr/0006`.

## Verifying releases and obtaining public signing keys

Releases are cut from an SSH-signed `v*` tag by `.github/workflows/publish.yml`, which uses
SHA-pinned actions and publishes to PyPI through Trusted Publishing (OIDC, no stored API
token) after a maintainer approves the `release` environment.

- **PyPI files** carry PEP 740 attestations from that workflow; PyPI shows them on each
  file's page.
- **GitHub release assets** (wheel and sdist) carry build-provenance attestations, and the
  bundle is attached as `provenance.intoto.jsonl`:

  ```bash
  gh attestation verify presidio_deident-<version>-py3-none-any.whl --repo presidio-v/presidio-deident
  ```

  A CycloneDX SBOM (`sbom.cdx.json`) is attached to each release.

- **Release tags** are SSH-signed with the organisation's release key. The public key is in
  [`allowed_signers`](allowed_signers):

  ```bash
  git -c gpg.ssh.allowedSignersFile=allowed_signers verify-tag <tag>
  ```

These keys sign the software. The keys that sign a *dataset release* belong to the releaser
and reach the buyer as a trust store: see [`docs/KEYS.md`](docs/KEYS.md).
