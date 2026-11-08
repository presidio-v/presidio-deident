# Keys

A release uses two keys. Both stay with the releaser; neither ever leaves its environment.

| Key | Made by | Used for | Who sees the public part |
|---|---|---|---|
| Signing key (Ed25519) | `deident keygen` | signing the release record | the buyer, as a trust store |
| Pseudonym key (32 random bytes) | `deident keygen` | HMAC pseudonyms, derived per recipient | nobody; it has no public part |

`keygen` writes both as `0600` files and refuses to overwrite an existing file. `run` refuses
a key file that other users can read.

## Giving the buyer the trust store

`keygen` prints the trust store, for example:

```json
{ "acme-data-release": { "alg": "ed25519", "public_key": "b2a5…d116" } }
```

Send it to the buyer through a channel other than the one that carries the data, and put the
public key (or its first 16 hex characters) in the licence or an annex. A buyer who received
the trust store together with the dataset has checked only that the two match each other.

## Rotating the signing key

Make a new key with `keygen`, and give the buyer a trust store that lists **both** public keys
for the same signer:

```json
{ "acme-data-release": { "alg": "ed25519", "public_key": ["<old>", "<new>"] } }
```

Old releases keep verifying under the old key, and new ones under the new key
(`tests/test_history.py::test_rotated_signing_key_keeps_old_releases_verifiable`).

## What is not supported

- **Revocation and validity periods.** A trust store has no dates. If a signing key leaks,
  remove it from the trust store, tell every buyer, and re-sign the releases they still use
  with a new key. Releases signed with the leaked key stop verifying for buyers who update.
- **Rotating the pseudonym key.** A new pseudonym key changes every pseudonym, so the next
  release no longer joins with the earlier ones. Keep the key for as long as releases to that
  recipient should stay joinable, and back it up like a database credential.
- **Keys in environment variables or a KMS.** Keys are files. Use your platform's secret
  storage to provision the files, and remove them after the run if you prefer.
