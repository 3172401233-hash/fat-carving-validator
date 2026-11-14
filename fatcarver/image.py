"""Read-only accessor for a disk image.

The image is opened with O_RDONLY and only ever read via pread, so the
scanner can never write back to the evidence file.
"""

import os


class DiskImage:
    def __init__(self, path):
        self.path = path
        self._fd = os.open(path, os.O_RDONLY)
        self.size = os.fstat(self._fd).st_size

    def read(self, offset, length):
        if offset < 0 or length < 0 or offset + length > self.size:
            raise IOError(
                "read outside image bounds: offset=%d length=%d size=%d"
                % (offset, length, self.size)
            )
        chunks = []
        remaining = length
        cursor = offset
        while remaining > 0:
            chunk = os.pread(self._fd, remaining, cursor)
            if not chunk:
                raise IOError("short read at offset %d" % cursor)
            chunks.append(chunk)
            cursor += len(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
