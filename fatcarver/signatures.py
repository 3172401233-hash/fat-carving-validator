"""Auxiliary signature evidence for well-known formats.

Signatures are *supporting evidence only*. A matching JPEG SOI/EOI or
%PDF-/%%EOF pair never proves a file was recovered intact: deleted-file
chains can be truncated, overlapped, or outright forged. The scanner
uses these checks solely to adjust candidate confidence and to annotate
the report.
"""

SIGNATURES = {
    "jpg": {"header": b"\xff\xd8\xff", "trailer": b"\xff\xd9", "label": "JPEG"},
    "jpeg": {"header": b"\xff\xd8\xff", "trailer": b"\xff\xd9", "label": "JPEG"},
    "pdf": {"header": b"%PDF-", "trailer": b"%%EOF", "label": "PDF"},
}


def signature_evidence(filename, content):
    """Return auxiliary signature evidence for a candidate, or None.

    The result is advisory: it must never be presented as proof of
    recovery.
    """
    ext = ""
    if "." in filename:
        ext = filename.rsplit(".", 1)[1].lower()
    sig = SIGNATURES.get(ext)
    if sig is None or not content:
        return None
    header_ok = content[: len(sig["header"])] == sig["header"]
    tail = content[-1024:] if len(content) > 1024 else content
    trailer_ok = sig["trailer"] in tail
    return {
        "format": sig["label"],
        "header_match": header_ok,
        "trailer_match": trailer_ok,
        "note": (
            "signature is auxiliary evidence only; it does not prove "
            "the candidate is intact or recoverable"
        ),
    }
