"""Command-line report printer: python -m fatcarver <image> [fat_copy]."""

import sys

from .scanner import FatScanner


def main(argv):
    if not argv:
        print("usage: python -m fatcarver <image> [fat_copy_index]")
        return 2
    fat_copy = int(argv[1]) if len(argv) > 1 else 0
    report = FatScanner(argv[0], fat_copy=fat_copy).scan()

    print("image:            %s" % report["image"])
    print("filesystem:       %s (cluster size %d bytes)"
          % (report["fat_type"], report["cluster_size"]))
    print("FAT copy used:    %d" % report["fat_copy_used"])
    print()
    if report["fat_copy_mismatches"]:
        print("!! FAT copies differ at %d region(s):"
              % len(report["fat_copy_mismatches"]))
        for m in report["fat_copy_mismatches"]:
            print("   copy %d offset 0x%X len %d"
                  % (m["copy"], m["offset"], m["length"]))
        print()
    if report["bad_clusters"]:
        print("!! bad-sector marks encountered in chains: %s"
              % ", ".join("0x%X" % c for c in report["bad_clusters"]))
        print()
    if report["overlapping_clusters"]:
        print("!! overlapping (cross-linked) clusters:")
        for ov in report["overlapping_clusters"]:
            print("   cluster 0x%X claimed by: %s"
                  % (ov["cluster"], ", ".join(ov["candidates"])))
        print()
    for note in report["notes"]:
        print("note: %s" % note)
    if report["notes"]:
        print()

    print("deleted-file candidates: %d" % len(report["candidates"]))
    for cand in report["candidates"]:
        print("-" * 72)
        print("path:          %s (from dir %s)"
              % (cand["path"], cand["source_directory"]))
        if cand["long_name"]:
            print("short name:    %s" % cand["short_name"])
        print("clusters:      %s"
              % ", ".join("0x%X" % c for c in cand["clusters"]))
        print("offsets:       %s"
              % ", ".join("0x%X" % o for o in cand["physical_offsets"]))
        print("declared size: %d bytes" % cand["declared_size"])
        print("recoverable:   %d bytes" % cand["recoverable_bytes"])
        print("termination:   %s" % cand["termination"])
        if cand["signature_evidence"]:
            sig = cand["signature_evidence"]
            print("signature:     %s header=%s trailer=%s (auxiliary only)"
                  % (sig["format"], sig["header_match"], sig["trailer_match"]))
        print("confidence:    %s (score %d)"
              % (cand["confidence"], cand["confidence_score"]))
        for issue in cand["issues"]:
            print("  issue:       %s" % issue)
        print("status:        %s" % cand["status"])
    print("-" * 72)
    print(report["disclaimer"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
