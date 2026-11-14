"""Read-only FAT12/16/32 deleted-file candidate scanner."""

import math

from .boot import BootSector
from .directory import parse_directory
from .fat import (
    FatTable,
    TERM_BAD,
    TERM_EOC,
    TERM_FREE,
    TERM_LOOP,
    TERM_RANGE,
    TERM_START_BAD,
    TERM_START_FREE,
    compare_fat_copies,
    follow_chain,
)
from .image import DiskImage
from .signatures import signature_evidence

# Terminations that mean the chain broke before its natural end.
BROKEN_TERMINATIONS = {
    TERM_LOOP: "chain loops back on itself",
    TERM_BAD: "chain hits a bad-sector mark",
    TERM_FREE: "chain hits an unallocated (zero) FAT entry",
    TERM_RANGE: "chain points outside the data area",
    TERM_START_FREE: "start cluster is marked free",
    TERM_START_BAD: "start cluster is marked bad",
}


class Candidate:
    """One deleted-entry recovery candidate. Never a promise of recovery."""

    def __init__(self, entry):
        self.entry = entry
        self.clusters = []
        self.offsets = []
        self.termination = None
        self.declared_size = entry.size
        self.recoverable_bytes = 0
        self.issues = []
        self.signature = None
        self.score = 100

    def penalize(self, points, reason):
        self.score -= points
        self.issues.append(reason)

    @property
    def confidence(self):
        if self.score >= 80:
            return "high"
        if self.score >= 50:
            return "medium"
        return "low"

    def to_dict(self):
        return {
            "path": self.entry.path,
            "source_directory": self.entry.dir_path or "/",
            "short_name": self.entry.short_name,
            "long_name": self.entry.lfn,
            "clusters": self.clusters,
            "physical_offsets": self.offsets,
            "declared_size": self.declared_size,
            "recoverable_bytes": self.recoverable_bytes,
            "termination": self.termination,
            "issues": self.issues,
            "signature_evidence": self.signature,
            "confidence": self.confidence,
            "confidence_score": self.score,
            "status": "candidate only - not a verified recovery",
        }


class FatScanner:
    def __init__(self, image_path, fat_copy=0):
        self.image_path = image_path
        self.fat_copy = fat_copy
        self.report = {
            "image": image_path,
            "fat_type": None,
            "fat_copy_used": fat_copy,
            "fat_copy_mismatches": [],
            "overlapping_clusters": [],
            "bad_clusters": [],
            "notes": [],
            "candidates": [],
            "disclaimer": (
                "All results are recovery candidates derived from directory "
                "entries and FAT chains. Signature matches are auxiliary "
                "evidence only and never prove successful recovery."
            ),
        }
        self._live_clusters = set()
        self._candidates = []
        self._dir_entries = []

    def scan(self):
        with DiskImage(self.image_path) as image:
            boot = BootSector(image.read(0, 512))
            self.boot = boot
            self.report["fat_type"] = "FAT%d" % boot.fat_type
            self.report["cluster_size"] = boot.cluster_size

            copies = []
            for i in range(boot.num_fats):
                copies.append(image.read(boot.fat_copy_offset(i), boot.fat_bytes))
            self.report["fat_copy_mismatches"] = compare_fat_copies(
                copies, boot.fat_type
            )
            if self.report["fat_copy_mismatches"]:
                self.report["notes"].append(
                    "FAT copies differ; chain walks use copy %d" % self.fat_copy
                )

            active = copies[min(self.fat_copy, len(copies) - 1)]
            self.fat = FatTable(active, boot.fat_type, boot.cluster_count)

            self._walk_directories(image)
            self._build_candidates(image)
            self._detect_overlaps()
            self.report["candidates"] = [c.to_dict() for c in self._candidates]
        return self.report

    # -- directory walking ------------------------------------------------

    def _read_chain_bytes(self, image, start_cluster):
        """Read a directory's cluster chain (defensive walk)."""
        clusters, term = follow_chain(
            self.fat, start_cluster, self.boot.cluster_count
        )
        if term != TERM_EOC:
            self.report["notes"].append(
                "directory chain at cluster %d terminated abnormally: %s"
                % (start_cluster, term)
            )
        chunks = []
        for cl in clusters:
            chunks.append(
                image.read(self.boot.cluster_to_offset(cl), self.boot.cluster_size)
            )
        return clusters, b"".join(chunks)

    def _walk_directories(self, image):
        boot = self.boot
        self._visited_dir_clusters = set()
        if boot.fat_type == 32:
            clusters, data = self._read_chain_bytes(image, boot.root_cluster)
            for cl in clusters:
                self._live_clusters.add(cl)
            self._walk_dir(image, data, "/", deleted_ancestor=False)
        else:
            root_off = boot.first_root_dir_sector * boot.bytes_per_sector
            root_len = boot.root_dir_sectors * boot.bytes_per_sector
            data = image.read(root_off, root_len) if root_len else b""
            self._walk_dir(image, data, "/", deleted_ancestor=False)

    def _walk_dir(self, image, data, path, deleted_ancestor):
        entries, notes = parse_directory(data, path)
        self.report["notes"].extend(notes)
        for entry in entries:
            self._dir_entries.append((entry, deleted_ancestor))
            if entry.is_directory and entry.start_cluster >= 2:
                if entry.start_cluster in self._visited_dir_clusters:
                    self.report["notes"].append(
                        "directory cycle at cluster 0x%X (%s); not recursed"
                        % (entry.start_cluster, entry.path)
                    )
                    continue
                self._visited_dir_clusters.add(entry.start_cluster)
                if entry.deleted:
                    # Deleted subdirectory: follow it, but mark the
                    # ancestry and never claim its clusters as live.
                    _, sub = self._read_chain_bytes(image, entry.start_cluster)
                    self._walk_dir(image, sub, entry.path, deleted_ancestor=True)
                elif not deleted_ancestor:
                    clusters, sub = self._read_chain_bytes(image, entry.start_cluster)
                    for cl in clusters:
                        self._live_clusters.add(cl)
                    self._walk_dir(image, sub, entry.path, deleted_ancestor=False)

    # -- candidate construction -------------------------------------------

    def _build_candidates(self, image):
        boot = self.boot
        for entry, deleted_ancestor in self._dir_entries:
            if entry.is_directory:
                continue
            if entry.deleted:
                self._candidates.append(self._make_candidate(image, entry))
            elif not deleted_ancestor:
                # Live file: reserve its clusters so deleted candidates
                # that reuse them get flagged.
                if entry.start_cluster >= 2 and entry.size > 0:
                    clusters, _ = follow_chain(
                        self.fat, entry.start_cluster, boot.cluster_count
                    )
                    self._live_clusters.update(clusters)

    def _make_candidate(self, image, entry):
        boot = self.boot
        cand = Candidate(entry)
        size = entry.size
        cluster_size = boot.cluster_size
        needed = math.ceil(size / cluster_size) if size else 0

        if entry.start_cluster < 2 or not boot.cluster_in_range(entry.start_cluster):
            cand.termination = TERM_RANGE
            cand.penalize(
                60,
                "start cluster 0x%X is outside the data area" % entry.start_cluster,
            )
            return cand

        clusters, term = follow_chain(
            self.fat, entry.start_cluster, boot.cluster_count
        )
        cand.clusters = clusters
        cand.offsets = [boot.cluster_to_offset(c) for c in clusters]
        cand.termination = term

        if term in BROKEN_TERMINATIONS:
            cand.penalize(40, BROKEN_TERMINATIONS[term])
            if term in (TERM_BAD, TERM_START_BAD):
                bad = clusters[-1] if clusters else entry.start_cluster
                self.report["bad_clusters"].append(bad)

        if len(clusters) > 1:
            contiguous = all(
                clusters[i + 1] == clusters[i] + 1
                for i in range(len(clusters) - 1)
            )
            if not contiguous:
                cand.penalize(10, "fragmented: cluster chain is not contiguous")

        allocated_hits = [c for c in clusters if c in self._live_clusters]
        if allocated_hits:
            cand.penalize(
                40,
                "clusters already allocated to live files/dirs: %s"
                % ", ".join("0x%X" % c for c in allocated_hits),
            )

        if self.report["fat_copy_mismatches"]:
            cand.penalize(15, "FAT copies disagree; chain may be unreliable")

        # How much data does the chain actually deliver?
        chain_bytes = len(clusters) * cluster_size
        if needed and len(clusters) < needed:
            cand.recoverable_bytes = min(chain_bytes, size)
            cand.penalize(
                40,
                "truncated: declared size needs %d clusters, chain yields %d"
                % (needed, len(clusters)),
            )
        else:
            cand.recoverable_bytes = (
                min(size, chain_bytes) if size else chain_bytes
            )

        # Auxiliary signature evidence (never conclusive).
        if cand.recoverable_bytes > 0 and clusters:
            content = self._read_candidate_bytes(image, cand)
            sig = signature_evidence(entry.name, content)
            if sig:
                cand.signature = sig
                if sig["header_match"] and sig["trailer_match"]:
                    cand.score = min(100, cand.score + 5)
                elif not sig["header_match"]:
                    cand.penalize(
                        10,
                        "extension suggests %s but header signature does not match"
                        % sig["format"],
                    )
        return cand

    def _read_candidate_bytes(self, image, cand):
        boot = self.boot
        remaining = cand.recoverable_bytes
        chunks = []
        for off in cand.offsets:
            if remaining <= 0:
                break
            take = min(remaining, boot.cluster_size)
            chunks.append(image.read(off, take))
            remaining -= take
        return b"".join(chunks)

    # -- cross-candidate analysis ------------------------------------------

    def _detect_overlaps(self):
        owners = {}
        for idx, cand in enumerate(self._candidates):
            for cl in cand.clusters:
                owners.setdefault(cl, []).append(idx)
        for cl, idxs in sorted(owners.items()):
            if len(idxs) > 1:
                paths = [self._candidates[i].entry.path for i in idxs]
                self.report["overlapping_clusters"].append(
                    {"cluster": cl, "candidates": paths}
                )
                for i in idxs:
                    others = [
                        self._candidates[j].entry.path for j in idxs if j != i
                    ]
                    self._candidates[i].penalize(
                        30,
                        "cross-linked: cluster 0x%X also claimed by %s"
                        % (cl, ", ".join(others)),
                    )


def scan_image(image_path, fat_copy=0):
    return FatScanner(image_path, fat_copy=fat_copy).scan()
