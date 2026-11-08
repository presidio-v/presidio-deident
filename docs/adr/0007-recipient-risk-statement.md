# ADR-0007: Recipient-risk statement

**Status:** Open, under legal review. Not built.

**Context:** after CJEU C-413/23 P (*EDPS v SRB*), whether pseudonymised data is personal data
depends on what the recipient can realistically do with it. The record cannot capture that.
A recipient-risk statement would add a fixed questionnaire about the recipient's means (other
data held, contractual bans on re-identification, access controls), answered by the releaser
and signed as the **releaser's declaration**.

**Why it is not built:** it is a legal declaration. Its questions, its wording and the line
between "documented" and "concluded" need legal review first. A badly worded statement would
invite a lab to read the record as an anonymisation certificate.

**Shape, if built:** a `recipient.toml` with fixed questions, each answered yes / no / not
known plus short text, copied verbatim into the record. The tool would compute no conclusion.
