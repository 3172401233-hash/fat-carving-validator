"""Boot sector / BPB parsing and FAT type detection."""

import struct


class BootSectorError(ValueError):
    pass


class BootSector:
    def __init__(self, sector):
        if len(sector) < 512:
            raise BootSectorError("boot sector shorter than 512 bytes")
        if sector[510] != 0x55 or sector[511] != 0xAA:
            raise BootSectorError("missing 0x55AA boot signature")

        self.bytes_per_sector = struct.unpack_from("<H", sector, 11)[0]
        self.sectors_per_cluster = sector[13]
        self.reserved_sectors = struct.unpack_from("<H", sector, 14)[0]
        self.num_fats = sector[16]
        self.root_entry_count = struct.unpack_from("<H", sector, 17)[0]
        total16 = struct.unpack_from("<H", sector, 19)[0]
        self.media = sector[21]
        fat16_size = struct.unpack_from("<H", sector, 22)[0]
        total32 = struct.unpack_from("<I", sector, 32)[0]

        if self.bytes_per_sector == 0 or self.bytes_per_sector & (self.bytes_per_sector - 1):
            raise BootSectorError("invalid bytes_per_sector")
        if self.sectors_per_cluster == 0:
            raise BootSectorError("sectors_per_cluster is zero")
        if self.num_fats == 0:
            raise BootSectorError("num_fats is zero")

        self.total_sectors = total16 if total16 else total32
        if self.total_sectors == 0:
            raise BootSectorError("total sector count is zero")

        self.fat_size_sectors = fat16_size
        self.root_cluster = 0  # FAT32 only
        if fat16_size == 0:
            # FAT32 BPB extensions
            self.fat_size_sectors = struct.unpack_from("<I", sector, 36)[0]
            self.root_cluster = struct.unpack_from("<I", sector, 44)[0] & 0x0FFFFFFF
            if self.fat_size_sectors == 0:
                raise BootSectorError("FAT size is zero in both BPB variants")

        self.root_dir_sectors = (
            (self.root_entry_count * 32) + (self.bytes_per_sector - 1)
        ) // self.bytes_per_sector
        self.first_fat_sector = self.reserved_sectors
        self.first_root_dir_sector = (
            self.reserved_sectors + self.num_fats * self.fat_size_sectors
        )
        self.first_data_sector = self.first_root_dir_sector + self.root_dir_sectors
        data_sectors = self.total_sectors - self.first_data_sector
        if data_sectors <= 0:
            raise BootSectorError("no data area")
        self.cluster_count = data_sectors // self.sectors_per_cluster

        # Microsoft FAT type determination: by count of clusters.
        if self.cluster_count < 4085:
            self.fat_type = 12
        elif self.cluster_count < 65525:
            self.fat_type = 16
        else:
            self.fat_type = 32

    @property
    def cluster_size(self):
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def fat_offset(self):
        return self.first_fat_sector * self.bytes_per_sector

    @property
    def fat_bytes(self):
        return self.fat_size_sectors * self.bytes_per_sector

    def fat_copy_offset(self, index):
        return (self.first_fat_sector + index * self.fat_size_sectors) * self.bytes_per_sector

    def cluster_to_offset(self, cluster):
        sector = self.first_data_sector + (cluster - 2) * self.sectors_per_cluster
        return sector * self.bytes_per_sector

    def cluster_in_range(self, cluster):
        return 2 <= cluster < 2 + self.cluster_count
