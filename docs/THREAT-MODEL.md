# Threat model: what a release record proves, and what it does not

## It proves

If `deident verify` passes with a trust store you obtained from the releaser out of band:

1. **Who signed.** The holder of the signing key named in your trust store signed this record.
2. **Which files.** The files in the directory are byte for byte the ones the record lists
   (SHA-256 and size).
3. **What the record says was done.** For each column the action, how many values changed,
   what PII types the detector found, which suppression lists were applied (by hash and date)
   and how many rows they removed, and the row counts in and out, which add up.
4. **Which release came first.** With `deident history`, which release follows which, for one
   dataset and one recipient.

## It does not prove

- **That the source is what the releaser says.** The record hashes the input file the tool was
  given. Nothing ties that file to a real system, contract or collection.
- **That the policy was adequate.** The record shows what was done, not whether it was enough.
  Choosing the column actions is the releaser's decision, and judging them is for counsel.
- **That detection was complete.** The detector is structural (regular expressions for six
  identifier types). It does not find names, postal addresses or identifiers written in
  prose. A count of zero means "nothing these patterns match", not "no personal data".
- **That the data is anonymous.** Whether the output is personal data depends on the recipient
  and what else it can use (CJEU C-413/23 P). The record is not an anonymisation opinion, an
  Expert Determination or a certification.
- **That the rights declarations are true.** `rights` is the releaser's statement, recorded as
  written.
- **That the timestamp is true.** `released_at` is the releaser's clock. It is signed, but no
  third party witnessed it.
- **That the releaser ran the tool honestly.** A releaser can edit the code, the data or the
  record before signing. The signature binds the releaser to what the record says; it does not
  stop the releaser from saying something false.

## Attacks it is designed to stop

| Attack | Stopped by |
|---|---|
| A file is swapped or edited after release | per-file SHA-256 and size |
| The record is edited (counts, actions, lists) | the signature over the record hash |
| The envelope is edited (date, source, version) | the unsigned envelope fields must equal the signed record |
| A record is presented as another dataset's, or as a release to another recipient | `@3` subject binding (`dataset-release`, `dataset_id`); the signed record names the recipient, and `history` requires one |
| A crafted record points outside the directory | plain file names only, no symlinks |
| An oversized or deeply nested JSON file | size-bounded, fail-closed parsing |

## Residual risks

- **Differencing across re-releases.** Two releases to the same recipient, one cycle apart,
  differ by the rows that were deleted in between. Their counts, and the data itself, can
  reveal who asked for deletion. Keep the cycle coarse where that matters.
- **Unkeyed hash lists.** Suppression lists in `sha256` and `ca-drop` format are unkeyed hashes
  of low-entropy values and can be reversed by whoever holds the list file. The release never
  contains a list.
- **Pseudonyms are joinable within a recipient.** By default all releases to one recipient
  share a pseudonym domain, so that recipient can join them on a shared identifier
  (`docs/adr/0005`).
- **A leaked signing key** lets someone sign records as the releaser until the buyer removes it
  from the trust store (`docs/KEYS.md`).
