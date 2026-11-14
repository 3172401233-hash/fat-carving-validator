"""End-to-end tests: build small FAT images, delete files, scan them."""

import hashlib
import os
import tempfile
import unittest

from fatcarver import scan_image
from fatcarver.boot import BootSector
from fatcarver.fat import (
    TERM_BAD,
    TERM_EOC,
    TERM_LOOP,
    TERM_START_FREE,
)
from tests.imgbuild import (
    ATTR_ARCHIVE,
    ATTR_DIRECTORY,
    FatImageBuilder,
    lfn_entries,
    make_83,
    short_entry,
)


def jpeg_bytes(size):
    body = bytearray(size)
    body[0:3] = b"\xff\xd8\xff"
    body[-2:] = b"\xff\xd9"
    for i in range(3, size - 2):
        body[i] = (i * 7) & 0xFF
    return bytes(body)


class ScanTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "image.img")

    def build_and_scan(self, builder, fat_copy=0):
        builder.write(self.path)
        return scan_image(self.path, fat_copy=fat_copy)

    @staticmethod
    def cand_by_name(report, name):
        # Deleted entries lose their first name character to the 0xE5
        # marker, rendered as "_" by the scanner.
        deleted_form = "_" + name[1:]
        for cand in report["candidates"]:
            if cand["path"].endswith(name) or cand["path"].endswith(deleted_form):
                return cand
        raise AssertionError(
            "candidate %r not found in %s"
            % (name, [c["path"] for c in report["candidates"]])
        )
class TestFat16Scenarios(ScanTestBase):
    def test_complete_deleted_file(self):
        b = FatImageBuilder(fat_type=16)
        content = jpeg_bytes(700)
        b.write_cluster(2, content[:512])
        b.write_cluster(3, content[512:])
        b.set_chain([2, 3])
        b.add_root_entries([
            short_entry(make_83("PHOTO.JPG"), ATTR_ARCHIVE, 2, 700, deleted=True),
        ])
        report = self.build_and_scan(b)

        self.assertEqual(report["fat_type"], "FAT16")
        cand = self.cand_by_name(report, "PHOTO.JPG")
        self.assertEqual(cand["clusters"], [2, 3])
        self.assertEqual(cand["termination"], TERM_EOC)
        self.assertEqual(cand["recoverable_bytes"], 700)
        self.assertEqual(cand["confidence"], "high")
        self.assertEqual(cand["signature_evidence"]["format"], "JPEG")
        self.assertTrue(cand["signature_evidence"]["header_match"])
        self.assertTrue(cand["signature_evidence"]["trailer_match"])
        # Even a perfect signature match is only a candidate.
        self.assertIn("candidate", cand["status"])
        # Physical offsets match the on-disk layout.
        boot = BootSector(b.build()[:512])
        self.assertEqual(cand["physical_offsets"][0], boot.cluster_to_offset(2))

    def test_fragmented_deleted_file(self):
        b = FatImageBuilder(fat_type=16)
        content = jpeg_bytes(1200)
        chunks = (content[:512], content[512:1024], content[1024:])
        for cl, chunk in zip((5, 9, 12), chunks):
            b.write_cluster(cl, chunk)
        b.set_chain([5, 9, 12])
        b.add_root_entries([
            short_entry(make_83("FRAG.JPG"), ATTR_ARCHIVE, 5, 1200, deleted=True),
        ])
        report = self.build_and_scan(b)
        cand = self.cand_by_name(report, "FRAG.JPG")
        self.assertEqual(cand["clusters"], [5, 9, 12])
        self.assertEqual(cand["termination"], TERM_EOC)
        self.assertTrue(any("fragmented" in i for i in cand["issues"]))
        self.assertEqual(cand["recoverable_bytes"], 1200)

    def test_same_name_in_two_dirs(self):
        b = FatImageBuilder(fat_type=16)
        # Live subdirectory at cluster 10.
        b.set_chain([10])
        b.add_root_entries([
            short_entry(make_83("SUBDIR"), ATTR_DIRECTORY, 10, 0),
        ])
        # Deleted PHOTO.JPG in root (cluster 2) and in SUBDIR (cluster 3).
        b.write_cluster(2, jpeg_bytes(300))
        b.write_cluster(3, jpeg_bytes(300))
        b.set_chain([2])
        b.set_chain([3])
        b.add_root_entries([
            short_entry(make_83("PHOTO.JPG"), ATTR_ARCHIVE, 2, 300, deleted=True),
        ])
        b.add_dir_entries(10, [
            short_entry(make_83("PHOTO.JPG"), ATTR_ARCHIVE, 3, 300, deleted=True),
        ])
        report = self.build_and_scan(b)
        photos = [c for c in report["candidates"]
                  if c["path"].endswith("_HOTO.JPG")]
        self.assertEqual(len(photos), 2)
        sources = sorted(c["source_directory"] for c in photos)
        self.assertEqual(sources, ["/", "/SUBDIR"])
        self.assertNotEqual(photos[0]["clusters"], photos[1]["clusters"])

    def test_loop_chain(self):
        b = FatImageBuilder(fat_type=16)
        b.write_cluster(50, b"A" * 512)
        b.write_cluster(51, b"B" * 512)
        b.set_entry(50, 51)
        b.set_entry(51, 50)  # loop
        b.add_root_entries([
            short_entry(make_83("LOOP.BIN"), ATTR_ARCHIVE, 50, 100000,
                        deleted=True),
        ])
        report = self.build_and_scan(b)
        cand = self.cand_by_name(report, "LOOP.BIN")
        self.assertEqual(cand["termination"], TERM_LOOP)
        self.assertEqual(cand["confidence"], "low")
        self.assertTrue(any("loop" in i for i in cand["issues"]))
    def test_forged_signature_does_not_prove_recovery(self):
        b = FatImageBuilder(fat_type=16)
        # Cluster holds a perfect-looking JPEG, but the declared size
        # needs 3 clusters and the chain delivers only 1.
        b.write_cluster(70, jpeg_bytes(512))
        b.set_chain([70])
        b.add_root_entries([
            short_entry(make_83("FAKE.JPG"), ATTR_ARCHIVE, 70, 1200,
                        deleted=True),
        ])
        report = self.build_and_scan(b)
        cand = self.cand_by_name(report, "FAKE.JPG")
        self.assertIsNotNone(cand["signature_evidence"])
        self.assertTrue(cand["signature_evidence"]["header_match"])
        self.assertTrue(any("truncated" in i for i in cand["issues"]))
        self.assertNotEqual(cand["confidence"], "high")
        self.assertEqual(cand["recoverable_bytes"], 512)
        self.assertIn("candidate", cand["status"])
        self.assertIn("never prove", report["disclaimer"])

    def test_cross_linked_candidates(self):
        b = FatImageBuilder(fat_type=16)
        b.write_cluster(20, b"X" * 512)
        b.write_cluster(21, b"Y" * 512)
        b.set_chain([20, 21])
        b.set_chain([21])  # second file starts on the shared cluster
        b.add_root_entries([
            short_entry(make_83("FIRST.BIN"), ATTR_ARCHIVE, 20, 900,
                        deleted=True),
            short_entry(make_83("SECOND.BIN"), ATTR_ARCHIVE, 21, 400,
                        deleted=True),
        ])
        report = self.build_and_scan(b)
        overlaps = report["overlapping_clusters"]
        self.assertTrue(any(ov["cluster"] == 21 for ov in overlaps))
        for name in ("FIRST.BIN", "SECOND.BIN"):
            cand = self.cand_by_name(report, name)
            self.assertTrue(any("cross-linked" in i for i in cand["issues"]))

    def test_chain_reusing_allocated_clusters(self):
        b = FatImageBuilder(fat_type=16)
        # Live file occupies clusters 30-31.
        b.write_cluster(30, b"L" * 512)
        b.write_cluster(31, b"L" * 512)
        b.set_chain([30, 31])
        # Deleted file's chain runs into cluster 31.
        b.write_cluster(32, b"D" * 512)
        b.set_entry(32, 31)
        b.add_root_entries([
            short_entry(make_83("KEEP.BIN"), ATTR_ARCHIVE, 30, 800),
            short_entry(make_83("GONE.BIN"), ATTR_ARCHIVE, 32, 900,
                        deleted=True),
        ])
        report = self.build_and_scan(b)
        cand = self.cand_by_name(report, "GONE.BIN")
        self.assertTrue(any("already allocated" in i for i in cand["issues"]))
        self.assertNotEqual(cand["confidence"], "high")

    def test_fat_copy_mismatch_reported(self):
        b = FatImageBuilder(fat_type=16)
        b.write_cluster(40, b"M" * 512)
        b.write_cluster(41, b"M" * 512)
        b.set_chain([40, 41])
        # Corrupt only the second FAT copy.
        b.set_entry(40, 0, fat_index=1)
        b.add_root_entries([
            short_entry(make_83("DIFF.BIN"), ATTR_ARCHIVE, 40, 900,
                        deleted=True),
        ])
        report = self.build_and_scan(b)
        self.assertTrue(report["fat_copy_mismatches"])
        cand = self.cand_by_name(report, "DIFF.BIN")
        self.assertTrue(any("FAT copies disagree" in i for i in cand["issues"]))
        # Scanning with copy 1 yields a different, truncated chain.
        report2 = self.build_and_scan(b, fat_copy=1)
        cand2 = self.cand_by_name(report2, "DIFF.BIN")
        self.assertEqual(cand2["termination"], TERM_START_FREE)

    def test_bad_cluster_mark(self):
        b = FatImageBuilder(fat_type=16)
        b.write_cluster(60, b"Z" * 512)
        b.set_entry(60, 61)
        b.set_entry(61, 0xFFF7)  # bad-sector mark
        b.add_root_entries([
            short_entry(make_83("BAD.BIN"), ATTR_ARCHIVE, 60, 900, deleted=True),
        ])
        report = self.build_and_scan(b)
        cand = self.cand_by_name(report, "BAD.BIN")
        self.assertEqual(cand["termination"], TERM_BAD)
        self.assertIn(61, report["bad_clusters"])
        self.assertTrue(any("bad-sector" in i for i in cand["issues"]))

    def test_deleted_long_filename(self):
        b = FatImageBuilder(fat_type=16)
        content = jpeg_bytes(300)
        b.write_cluster(80, content)
        b.set_chain([80])
        short = make_83("VACATI~1.JPG")
        entries = lfn_entries("Vacation Photo 2024.jpg", short, deleted=True)
        entries.append(short_entry(short, ATTR_ARCHIVE, 80, 300, deleted=True))
        b.add_root_entries(entries)
        report = self.build_and_scan(b)
        cand = self.cand_by_name(report, "Vacation Photo 2024.jpg")
        self.assertEqual(cand["long_name"], "Vacation Photo 2024.jpg")
        self.assertEqual(cand["termination"], TERM_EOC)

    def test_image_not_modified(self):
        b = FatImageBuilder(fat_type=16)
        b.write_cluster(2, jpeg_bytes(300))
        b.set_chain([2])
        b.add_root_entries([
            short_entry(make_83("RO.JPG"), ATTR_ARCHIVE, 2, 300, deleted=True),
        ])
        b.write(self.path)
        with open(self.path, "rb") as fh:
            before = hashlib.sha256(fh.read()).hexdigest()
        scan_image(self.path)
        with open(self.path, "rb") as fh:
            after = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(before, after)


class TestFat12(ScanTestBase):
    def test_deleted_file_fat12(self):
        b = FatImageBuilder(fat_type=12)
        content = jpeg_bytes(600)
        b.write_cluster(2, content[:512])
        b.write_cluster(3, content[512:])
        b.set_chain([2, 3])
        b.add_root_entries([
            short_entry(make_83("OLD.JPG"), ATTR_ARCHIVE, 2, 600, deleted=True),
        ])
        report = self.build_and_scan(b)
        self.assertEqual(report["fat_type"], "FAT12")
        cand = self.cand_by_name(report, "OLD.JPG")
        self.assertEqual(cand["clusters"], [2, 3])
        self.assertEqual(cand["termination"], TERM_EOC)
        self.assertEqual(cand["recoverable_bytes"], 600)


class TestFat32(ScanTestBase):
    def test_deleted_file_fat32(self):
        b = FatImageBuilder(fat_type=32)
        content = jpeg_bytes(600)
        b.write_cluster(5, content[:512])
        b.write_cluster(6, content[512:])
        b.set_chain([5, 6])
        b.set_chain([b.root_cluster])  # root dir chain
        b.add_dir_entries(b.root_cluster, [
            short_entry(make_83("BIG.JPG"), ATTR_ARCHIVE, 5, 600, deleted=True),
        ])
        report = self.build_and_scan(b)
        self.assertEqual(report["fat_type"], "FAT32")
        cand = self.cand_by_name(report, "BIG.JPG")
        self.assertEqual(cand["clusters"], [5, 6])
        self.assertEqual(cand["termination"], TERM_EOC)
        self.assertEqual(cand["recoverable_bytes"], 600)


if __name__ == "__main__":
    unittest.main()
