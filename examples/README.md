# Worked example (synthetic data)

All names, addresses and numbers here are invented.

`sample-release/` is this example, already run and signed; `sample-trust.json` holds its public
key. The private keys were discarded. Verify it with
`deident verify sample-release --trust sample-trust.json`. A test checks that it keeps
verifying, so it doubles as a compatibility vector for the record format.

To run the example yourself:

```bash
cd examples
deident inspect tickets.csv
deident keygen --signer acme-data-release --sign-key /tmp/sign.key --pseudonym-key /tmp/pseudo.key > trust.json
deident run --policy policy.toml --input tickets.csv --out release \
            --sign-key /tmp/sign.key --pseudonym-key /tmp/pseudo.key
deident verify release --trust trust.json
```

Expected: 3 rows in, 1 suppressed (the opt-out list holds Bob's address), and 2 out. The phone
number in the first ticket becomes `<PHONE_NUMBER>`; the ticket ids become 32-character
pseudonyms; the email and name columns are gone. `release/release.json` records all of this as
counts. Keys belong outside the repository (`*.key` is git-ignored).
