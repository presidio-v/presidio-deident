"""presidio-deident: de-identify a dataset and sign a release record the buyer verifies offline.

A release is a directory holding the transformed data file, ``release.json`` (the record:
what was removed, what remained, which suppression lists, which declared sources and
rights, for which recipient, as counts and hashes) and ``release.evidence.json`` (an
``evidence-ref@3`` envelope signing the record's content hash; see docs/adr/0004).

The record documents what was done; it never states that the output is anonymous.
"""

__version__ = "0.7.1"

RECORD_SCHEMA = "presidio-deident/dataset-release@1"
FRAMEWORK = "dataset-release"
