# ADR-0006: Suppression list formats

**Status:** Accepted (2026-11-08). `ca-drop` added in v0.6.0.

**Context:** opt-out and deletion lists remove rows before release. The record never carries
list entries, only the list file's SHA-256, its date, the number of entries and the number of
rows matched. Lists are matched in memory.

**Formats:**
- `plain`: the identifiers themselves, normalised (`strip`, `lower`);
- `sha256`: hex SHA-256 of the normalised identifier;
- `ca-drop`: one California DROP deletion-list CSV (`Id,Hash`, SHA-256 in Base64), with DROP's
  own standardisation as `drop-email` (remove whitespace, lowercase) or `drop-phone` (digits
  only, the last 10). Tested against the official CalPrivacy vectors. A file with another
  header, such as DROP's `Removed` file, is refused.

**Why unkeyed hashes:** deletion platforms distribute unkeyed hashes, so the matcher must
accept them. A keyed format would add a key and protect nothing the record exposes.

**Risk:** an unkeyed hash of a low-entropy value, such as a phone number, can be reversed by
whoever holds the list file. The release never contains a list.

**Not yet supported:** DROP's composite lists (name + date of birth + ZIP, name + VIN), which
hash each field and then the concatenation. They will be added when a releaser needs them.
