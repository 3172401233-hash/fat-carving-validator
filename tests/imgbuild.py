"""In-memory FAT12/16/32 image builder for tests.

Builds small, spec-shaped images: boot sector, N FAT copies, root
directory region (FAT12/16) and a data area. Tests use it to lay out
deleted files, fragmented chains, loops, cross-links, bad-cluster marks
and FAT-copy mismatches without touching real media.
"""

import struct

ATTR_ARCHIVE = 0x20
ATTR_DIRECTORY = 0x10
ATTR_LFN = 0x0F


def lfn_checksum(short_name_11):
    total = 0
    for b in short_name_11:
        total = (((total & 1) << 7) + (total >> 1) + b) & 0xFF
    return total


def short_entry(name11, attr, cluster, size, deleted=False):
    """name11: exactly 11 bytes (space-padded 8.3)."""
    assert len(name11) == 11
    raw = bytearray(32)
    raw[0:11] = name11
    raw[11] = attr
    struct.pack_into("<H", raw, 20, (cluster >> 16) & 0xFFFF)
    struct.pack_into("<H", raw, 26, cluster & 0xFFFF)
    struct.pack_into("<I", raw, 28, size)
    if deleted:
        raw[0] = 0xE5
    return bytes(raw)


def make_83(name):
    """Convert 'FILE.TXT' to an 11-byte 8.3 name."""
    if "." in name:
        base, ext = name.rsplit(".", 1)
    else:
        base, ext = name, ""
    return base.upper().ljust(8).encode("ascii")[:8] + ext.upper().ljust(3).encode("ascii")[:3]


def lfn_entries(long_name, short_name_11, deleted=False):
    """Build LFN entries for `long_name`, in on-disk order (last part
    first, first part last, immediately before the short entry)."""
    chars = long_name
    parts = []
    while chars:
        parts.append(chars[:13])
        chars = chars[13:]
    checksum = lfn_checksum(short_name_11)
    entries = []
    total = len(parts)
    for idx in range(total - 1, -1, -1):
        part = parts[idx]
        seq = idx + 1
        if idx == total - 1:
            seq |= 0x40
        raw = bytearray(32)
        raw[0] = seq
        raw[11] = ATTR_LFN
        raw[13] = checksum
        struct.pack_into("<H", raw, 26, 0xFFFF)  # must be zero; keep simple
        struct.pack_into("<H", raw, 26, 0)
        encoded = part.encode("utf-16-le")
        # 13 UTF-16 chars across offsets 1-10, 14-25, 28-31
        slots = [(1, 10), (14, 12), (28, 4)]
        buf = bytearray()
        pos = 0
        padded = encoded + b"\x00\x00"
        padded = padded.ljust(26, b"\xff")
        for start, length in slots:
            raw[start:start + length] = padded[pos:pos + length]
            pos += length
        if deleted:
            raw[0] = 0xE5
        entries.append(bytes(raw))
    return entries


class FatImageBuilder:
    def __init__(self, fat_type=16, num_clusters=None, sector_size=512,
                 sectors_per_cluster=1, num_fats=2, root_entries=512,
                 reserved=1, media=0xF8):
        self.fat_type = fat_type
        self.sector_size = sector_size
        self.spc = sectors_per_cluster
        self.num_fats = num_fats
        self.root_entries = root_entries if fat_type != 32 else 0
        self.reserved = reserved
        self.media = media
        if num_clusters is None:
            num_clusters = {12: 100, 16: 4200, 32: 65600}[fat_type]
        self.num_clusters = num_clusters

        entry_bytes = {12: 1.5, 16: 2, 32: 4}[fat_type]
        fat_bytes_needed = int((num_clusters + 2) * entry_bytes) + 2
        self.fat_sectors = (fat_bytes_needed + sector_size - 1) // sector_size
        self.root_dir_sectors = (
            (self.root_entries * 32) + sector_size - 1
        ) // sector_size
        self.total_sectors = (
            reserved + num_fats * self.fat_sectors
            + self.root_dir_sectors + num_clusters * self.spc
        )
        self.root_cluster = 2 if fat_type == 32 else 0

        fat_len = self.fat_sectors * sector_size
        self.fats = [bytearray(fat_len) for _ in range(num_fats)]
        self._init_fat_headers()

        self.root_dir = bytearray(self.root_dir_sectors * sector_size)
        self._root_pos = 0
        # cluster number -> bytearray content
        self.cluster_data = {}
        # entries to place inside a directory cluster (FAT32 root or subdirs)
        self.dir_cluster_entries = {}
        self._dir_cluster_pos = {}

    # -- FAT helpers -------------------------------------------------------

    def _init_fat_headers(self):
        eoc = {12: 0xFF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[self.fat_type]
        for fat in self.fats:
            self._set_entry_in(fat, 0, self.media | (0xF00 if self.fat_type == 12
                               else 0xFF00 if self.fat_type == 16 else 0x0FFFFF00))
            self._set_entry_in(fat, 1, eoc | ({12: 0x700, 16: 0x7000, 32: 0x07000000}[self.fat_type]))

    def _set_entry_in(self, fat, n, value):
        if self.fat_type == 12:
            off = n + n // 2
            if n % 2 == 0:
                fat[off] = value & 0xFF
                fat[off + 1] = (fat[off + 1] & 0xF0) | ((value >> 8) & 0x0F)
            else:
                fat[off] = (fat[off] & 0x0F) | ((value << 4) & 0xF0)
                fat[off + 1] = (value >> 4) & 0xFF
        elif self.fat_type == 16:
            struct.pack_into("<H", fat, n * 2, value & 0xFFFF)
        else:
            struct.pack_into("<I", fat, n * 4, value & 0x0FFFFFFF)

    def set_entry(self, cluster, value, fat_index=None):
        """Set a FAT entry in all copies, or one copy if fat_index given."""
        targets = range(self.num_fats) if fat_index is None else [fat_index]
        for i in targets:
            self._set_entry_in(self.fats[i], cluster, value)

    def set_chain(self, clusters, fat_index=None):
        """Link clusters into a chain ending with EOC."""
        eoc = {12: 0xFFF, 16: 0xFFFF, 32: 0x0FFFFFFF}[self.fat_type]
        for i, cl in enumerate(clusters):
            nxt = clusters[i + 1] if i + 1 < len(clusters) else eoc
            self.set_entry(cl, nxt, fat_index=fat_index)

    # -- content helpers ----------------------------------------------------

    @property
    def cluster_size(self):
        return self.sector_size * self.spc

    def write_cluster(self, cluster, data):
        buf = bytearray(self.cluster_size)
        buf[:len(data)] = data[:self.cluster_size]
        self.cluster_data[cluster] = buf

    def add_root_entries(self, entries):
        assert self.fat_type != 32, "use add_dir_entries for FAT32 root"
        for e in entries:
            self.root_dir[self._root_pos:self._root_pos + 32] = e
            self._root_pos += 32

    def add_dir_entries(self, dir_cluster, entries):
        lst = self.dir_cluster_entries.setdefault(dir_cluster, [])
        lst.extend(entries)

    # -- assembly ------------------------------------------------------------

    def _boot_sector(self):
        bs = bytearray(self.sector_size)
        bs[0:3] = b"\xeb\x3c\x90"
        bs[3:11] = b"PYTEST  "
        struct.pack_into("<H", bs, 11, self.sector_size)
        bs[13] = self.spc
        struct.pack_into("<H", bs, 14, self.reserved)
        bs[16] = self.num_fats
        struct.pack_into("<H", bs, 17, self.root_entries)
        if self.total_sectors < 0x10000:
            struct.pack_into("<H", bs, 19, self.total_sectors)
        else:
            struct.pack_into("<I", bs, 32, self.total_sectors)
        bs[21] = self.media
        if self.fat_type == 32:
            struct.pack_into("<H", bs, 22, 0)
            struct.pack_into("<I", bs, 36, self.fat_sectors)
            struct.pack_into("<I", bs, 44, self.root_cluster)
            struct.pack_into("<H", bs, 48, 1)   # FSInfo sector
            struct.pack_into("<H", bs, 50, 6)   # backup boot sector
            bs[64] = 0x80
            bs[66] = 0x29
            struct.pack_into("<I", bs, 67, 0x12345678)
            bs[71:82] = b"NO NAME    "
            bs[82:90] = b"FAT32   "
        else:
            struct.pack_into("<H", bs, 22, self.fat_sectors)
            bs[36] = 0x80
            bs[38] = 0x29
            struct.pack_into("<I", bs, 39, 0x12345678)
            bs[43:54] = b"NO NAME    "
            bs[54:62] = b"FAT12   " if self.fat_type == 12 else b"FAT16   "
        bs[510] = 0x55
        bs[511] = 0xAA
        return bytes(bs)

    def build(self):
        # Materialize directory-cluster entries into cluster data.
        for cluster, entries in self.dir_cluster_entries.items():
            buf = bytearray(self.cluster_size)
            pos = 0
            for e in entries:
                buf[pos:pos + 32] = e
                pos += 32
            self.cluster_data[cluster] = buf

        image = bytearray(self.total_sectors * self.sector_size)
        image[0:self.sector_size] = self._boot_sector()

        fat_start = self.reserved * self.sector_size
        fat_len = self.fat_sectors * self.sector_size
        for i, fat in enumerate(self.fats):
            off = fat_start + i * fat_len
            image[off:off + fat_len] = fat

        root_off = (self.reserved + self.num_fats * self.fat_sectors) * self.sector_size
        image[root_off:root_off + len(self.root_dir)] = self.root_dir

        data_start_sector = (
            self.reserved + self.num_fats * self.fat_sectors + self.root_dir_sectors
        )
        for cluster, buf in self.cluster_data.items():
            sector = data_start_sector + (cluster - 2) * self.spc
            off = sector * self.sector_size
            image[off:off + self.cluster_size] = buf
        return bytes(image)

    def write(self, path):
        data = self.build()
        with open(path, "wb") as fh:
            fh.write(data)
        return path
