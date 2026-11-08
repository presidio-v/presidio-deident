# ADR-0005: Default pseudonym domain

**Status:** Open, under legal review. Built with the default "recipient".

**Context:** the pseudonym key is derived per *domain*:
`HMAC(master, "presidio-deident/v1/pseudonym\0" + domain)`. The same value in the same domain
always gets the same pseudonym; different domains get unlinkable pseudonyms. The default
domain is the recipient, and a policy can set `pseudonym_domain`. The record carries the
scheme and the domain label, never the key.

**The trade-off is a licensing term, not a technical one:**

| Default | Two tables of one dataset to one lab | Two different datasets to one lab | Re-release after a deletion cycle |
|---|---|---|---|
| **recipient** (built) | can join | **can join** | stable |
| recipient + dataset | cannot join, unless a shared domain is set | cannot join | stable |

With "recipient", a lab that licenses two datasets from the same releaser can join them on a
shared identifier. That may be wanted, or it may be what the licence forbids.

**Until decided:** the default stays "recipient". Releasers who need datasets to stay unlinkable
set `pseudonym_domain` per dataset.
