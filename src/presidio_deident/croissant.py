"""A minimal Croissant (MLCommons) description of a release, carrying the release record's hash.

Only the dataset and its file objects are described. The signed record stays the
authoritative statement; the Croissant file points to it by hash so a catalogue entry can
be traced back to the release.
"""

from __future__ import annotations

from . import FRAMEWORK

ENCODING = {
    ".csv": "text/csv",
    ".jsonl": "application/jsonlines",
    ".ndjson": "application/jsonlines",
}


def croissant(record: dict, record_hash: str, *, name: str | None = None) -> dict:
    files = []
    for out in record["outputs"]:
        suffix = "." + out["name"].rsplit(".", 1)[-1].lower() if "." in out["name"] else ""
        files.append(
            {
                "@type": "cr:FileObject",
                "@id": out["name"],
                "name": out["name"],
                "contentUrl": out["name"],
                "contentSize": f"{out['bytes']} B",
                "encodingFormat": ENCODING.get(suffix, "application/octet-stream"),
                "sha256": out["sha256"],
            }
        )
    return {
        "@context": {
            "@language": "en",
            "@vocab": "https://schema.org/",
            "cr": "http://mlcommons.org/croissant/",
            "sc": "https://schema.org/",
            "dct": "http://purl.org/dc/terms/",
        },
        "@type": "sc:Dataset",
        "conformsTo": "http://mlcommons.org/croissant/1.0",
        "name": name or record["dataset_id"],
        "description": (
            f"Release of {record['dataset_id']} for {record['recipient']}, "
            f"{record['released_at']}. The signed release record (release.json) documents "
            "the de-identification applied; this file is a pointer to it."
        ),
        "identifier": f"{FRAMEWORK}:sha256:{record_hash}",
        "datePublished": record["released_at"],
        "distribution": files,
    }
