# Test vectors for `dataset-release@1`

Each entry in `expectations.json` names a release directory, a trust store, whether it must
verify, and exactly which checks must fail. All data is synthetic. A verifier, ours or
anyone's, should reproduce these results. The vectors ship inside the package:

```bash
python -c "import presidio_deident, pathlib; print(pathlib.Path(presidio_deident.__file__).parent / 'vectors')"
```

Append-only: a published vector is never edited or removed.
