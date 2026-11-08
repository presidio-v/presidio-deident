# ADR-0008: Publishing

**Status:** Accepted (2026-11-08).

**Decision:** presidio-deident is open source (MIT) on GitHub and PyPI, because the offering
rests on "the buyer verifies with a free, open-source tool".

- Releases are SSH-signed tags; PyPI publishing uses Trusted Publishing (OIDC, no stored
  token) from `.github/workflows/publish.yml`, behind a `release` environment that a maintainer
  approves.
- Each GitHub release carries the wheel, the sdist, a CycloneDX SBOM and build provenance.
- The repository follows the presidio-v hardening baseline (ADR-0010).
- The Dataset Release page on presidio-group.eu links the repository and the sample verify
  command once the package is on PyPI.
