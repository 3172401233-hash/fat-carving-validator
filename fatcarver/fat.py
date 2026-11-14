"""FAT table access, chain walking, and FAT-copy comparison."""


# Termination reasons for a cluster chain walk.
TERM_EOC = "end_of_chain"          # reached a valid end-of-chain mark
TERM_LOOP = "loop_detected"        # chain revisits a cluster
TERM_BAD = "bad_cluster"           # chain hits a bad-sector mark
TERM_FREE = "free_cluster"         # chain hits a zero (unallocated) entry
TERM_RANGE = "out_of_range"        # chain points outside the data area
TERM_START_FREE = "start_free"     # the start cluster itself is free
TERM_START_BAD = "start_bad"       # the start cluster itself is marked bad


class FatTable:
    """Parsed view over one FAT copy (FAT12/16/32)."""

    def __init__(self, data, fat_type, cluster_count):
        self.data = data
        self.fat_type = fat_type
        self.cluster_count = cluster_count
        if fat_type == 12:
            self.eoc_min = 0x0FF8
            self.bad_value = 0x0FF7
        elif fat_type == 16:
            self.eoc_min = 0xFFF8
            self.bad_value = 0xFFF7
        else:
            self.eoc_min = 0x0FFFFFF8
            self.bad_value = 0x0FFFFFF7

    def entry(self, cluster):
        n = cluster
        if self.fat_type == 12:
            off = n + n // 2
            if off + 1 >= len(self.data):
                return None
            pair = self.data[off] | (self.data[off + 1] << 8)
            return (pair & 0x0FFF) if n % 2 == 0 else (pair >> 4)
        if self.fat_type == 16:
            off = n * 2
            if off + 1 >= len(self.data):
                return None
            return self.data[off] | (self.data[off + 1] << 8)
        off = n * 4
        if off + 3 >= len(self.data):
            return None
        return int.from_bytes(self.data[off:off + 4], "little") & 0x0FFFFFFF

    def is_free(self, value):
        return value == 0

    def is_bad(self, value):
        return value == self.bad_value

    def is_eoc(self, value):
        return value is not None and value >= self.eoc_min


def follow_chain(fat, start, max_clusters):
    """Follow a cluster chain. Returns (clusters, termination_reason).

    The walk is defensive: loops, bad marks, free entries and out-of-range
    pointers all terminate the walk and are reported, never silently
    ignored.
    """
    clusters = []
    first = fat.entry(start)
    if first is None:
        return clusters, TERM_RANGE
    if fat.is_free(first):
        return clusters, TERM_START_FREE
    if fat.is_bad(first):
        return clusters, TERM_START_BAD

    seen = set()
    current = start
    while True:
        if current in seen:
            return clusters, TERM_LOOP
        seen.add(current)
        clusters.append(current)
        if len(clusters) >= max_clusters:
            # Safety bound: a chain can never legitimately exceed the
            # number of clusters in the volume.
            return clusters, TERM_LOOP
        value = fat.entry(current)
        if value is None or not (2 <= value < 2 + fat.cluster_count) and not fat.is_eoc(value) and not fat.is_bad(value):
            return clusters, TERM_RANGE
        if fat.is_eoc(value):
            return clusters, TERM_EOC
        if fat.is_free(value):
            return clusters, TERM_FREE
        if fat.is_bad(value):
            return clusters, TERM_BAD
        current = value


def compare_fat_copies(copies, fat_type):
    """Compare raw FAT copies byte-by-byte.

    Returns a list of {"offset", "values"} entries describing the first
    differing byte of each mismatch run. Differences between FAT copies
    are common on live systems but matter for forensics: chain walks may
    disagree depending on which copy is trusted.
    """
    mismatches = []
    if len(copies) < 2:
        return mismatches
    base = copies[0]
    for idx, other in enumerate(copies[1:], start=1):
        limit = min(len(base), len(other))
        pos = 0
        while pos < limit:
            if base[pos] != other[pos]:
                start = pos
                while pos < limit and base[pos] != other[pos]:
                    pos += 1
                mismatches.append({
                    "copy": idx,
                    "offset": start,
                    "length": pos - start,
                    "copy0_bytes": base[start:pos].hex(),
                    "copyN_bytes": other[start:pos].hex(),
                })
            else:
                pos += 1
        if len(base) != len(other):
            mismatches.append({
                "copy": idx,
                "offset": limit,
                "length": abs(len(base) - len(other)),
                "copy0_bytes": "",
                "copyN_bytes": "",
            })
    return mismatches
