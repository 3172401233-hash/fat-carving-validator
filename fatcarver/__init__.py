"""Read-only FAT12/16/32 deleted-file candidate scanner.

All results are *candidates* only. Nothing in this package writes to the
image under inspection, and no heuristic (including file signatures) is
proof of successful recovery.
"""

from .scanner import FatScanner, scan_image

__all__ = ["FatScanner", "scan_image"]
