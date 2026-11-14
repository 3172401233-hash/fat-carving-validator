"""FAT directory entry parsing, including long file names (LFN)."""

import string

ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LFN = 0x0F

ENTRY_FREE = 0x00
ENTRY_DELETED = 0xE5

_PRINTABLE = set(bytes(string.printable, "ascii"))


def _decode_short_name(raw):
    name = raw[0:8].decode("ascii", "replace").rstrip()
    ext = raw[8:11].decode("ascii", "replace").rstrip()
    return name + ("." + ext if ext else "")


def _looks_plausible(raw):
    """Heuristic: a deleted entry should still look like a name."""
    body = raw[1:11]
    return all(b in _PRINTABLE or b == 0x20 for b in body)


class DirEntry:
    def __init__(self, raw, lfn_parts, dir_path, slot_index):
        self.raw = raw
        self.dir_path = dir_path
        self.slot_index = slot_index
        self.deleted = raw[0] == ENTRY_DELETED
        self.attr = raw[11]
        self.is_directory = bool(self.attr & ATTR_DIRECTORY)
        self.is_volume = bool(self.attr & ATTR_VOLUME_ID)
        self.short_name = _decode_short_name(raw)
        if self.deleted:
            # First character was overwritten with 0xE5.
            self.short_name = "_" + self.short_name[1:]
        self.lfn = self._join_lfn(lfn_parts) if lfn_parts else None
        self.name = self.lfn or self.short_name
        cluster_high = int.from_bytes(raw[20:22], "little")
        cluster_low = int.from_bytes(raw[26:28], "little")
        self.start_cluster = (cluster_high << 16) | cluster_low
        self.size = int.from_bytes(raw[28:32], "little")

    @staticmethod
    def _join_lfn(lfn_parts):
        # lfn_parts: fragment texts in on-disk order. The on-disk layout
        # stores the LAST fragment first, so the name is the reversed
        # join. Sequence numbers are unreliable here anyway: deletion
        # overwrites the first byte (the sequence field) with 0xE5.
        return "".join(reversed(lfn_parts))

    @property
    def path(self):
        base = self.dir_path.rstrip("/")
        return (base + "/" + self.name) if base else "/" + self.name


def _parse_lfn_fragment(raw):
    """Return the fragment text for one LFN entry."""
    chars = raw[1:11] + raw[14:26] + raw[28:32]
    text = chars.decode("utf-16-le", "replace")
    # Trim at the first NUL; trailing 0xFFFF padding is also dropped.
    cut = len(text)
    for i, ch in enumerate(text):
        if ch == "\x00" or ch == "\uffff":
            cut = i
            break
    return text[:cut]


def parse_directory(data, dir_path):
    """Parse a directory table. Returns (entries, notes).

    `entries` contains file/subdirectory DirEntry objects (deleted and
    live). `notes` records anomalies such as implausible deleted entries
    that were skipped.
    """
    entries = []
    notes = []
    lfn_parts = []
    for slot in range(0, len(data) - 31, 32):
        raw = data[slot:slot + 32]
        first = raw[0]
        if first == ENTRY_FREE:
            break
        if raw[11] == ATTR_LFN:
            lfn_parts.append(_parse_lfn_fragment(raw))
            continue
        if first == ENTRY_DELETED:
            if not _looks_plausible(raw):
                notes.append(
                    "slot %d in %s: deleted entry skipped (implausible name bytes)"
                    % (slot // 32, dir_path or "/")
                )
                lfn_parts = []
                continue
        entry = DirEntry(raw, lfn_parts, dir_path, slot // 32)
        lfn_parts = []
        if entry.is_volume:
            continue
        if entry.short_name in (".", ".."):
            continue
        entries.append(entry)
    return entries, notes
