"""Chunked, integrity-validating readers for docker image layers.

A layer blob is either an uncompressed tar or a tar wrapped in gzip, xz or
bzip2.  The readers in this module never buffer a whole layer and never write
unpacked bytes to disk: they expose a normal ``read()`` file-like interface
that yields decompressed bytes in fixed-size chunks while the tar streamer
consumes them.

Integrity guarantees that plain ``tarfile.open(..., mode="r|*")`` cannot give:

* the compressed stream is read to its real end; a missing trailer or any
  truncation raises :class:`LayerStreamError` instead of being silently
  accepted once the tar end-of-archive marker has been seen;
* gzip CRC32/ISIZE, xz CRC and bzip2 CRC checks are enforced by the standard
  library decompressors and surfaced as errors;
* concatenated gzip members, xz streams and bzip2 streams are decoded as one
  continuous byte stream (a member boundary may fall inside a tar header or
  file body), and every member must be complete and valid;
* bytes after the tar end-of-archive marker are drained and must consist of
  zero blocks at most; any non-zero trailing data fails the layer.
"""

from __future__ import annotations

import bz2
import io
import lzma
import zlib

# Keep each raw read and each held output chunk small; the full layer is never
# resident in memory.
READ_CHUNK_SIZE = 64 * 1024

GZIP_MAGIC = b"\x1f\x8b"
XZ_MAGIC = b"\xfd7zXZ\x00"
BZ2_MAGIC = b"BZh"

#: category -> stable machine-readable error code used in HTTP responses.
ERROR_CODES = {
    "truncated": "layer_compression_truncated",
    "checksum": "layer_compression_corrupt",
    "trailing": "layer_tail_invalid",
}


class LayerStreamError(Exception):
    """Raised when a layer's compressed stream or tar tail cannot be trusted."""

    def __init__(self, category: str, message: str) -> None:
        super().__init__(message)
        self.category = category
        self.code = ERROR_CODES[category]
        self.message = message


class ValidatingLayerReader(io.BufferedIOBase):
    """Read-only stream with full end-to-end validation of one layer blob.

    ``raw`` must be a binary file-like object positioned at the first byte of
    the layer.  The compression format is detected from magic bytes, so the
    same reading path serves uncompressed layers and all three compression
    formats.
    """

    def __init__(self, raw) -> None:
        self._raw = raw
        self._buf = bytearray()
        # Raw bytes already fetched (e.g. the magic-byte probe) that still
        # have to be fed to the decompressor.
        self._pending = b""
        self._raw_eof = False
        self._stream_ok = False
        self._kind = "plain"
        self._dec = None
        self._members = 0
        self._detect_format()

    # ------------------------------------------------------------------ info
    @property
    def kind(self) -> str:
        """Compression format: ``plain``, ``gzip``, ``xz`` or ``bz2``."""

        return self._kind

    @property
    def member_count(self) -> int:
        """Number of concatenated compressed members seen (1 for plain)."""

        return self._members

    def readable(self) -> bool:
        return True

    # ------------------------------------------------------------- detection
    def _detect_format(self) -> None:
        head = self._raw.read(6)
        if not head:
            # An empty blob is a plain (and invalid) tar; let the tar parser
            # produce the structural error.
            return
        self._pending = head
        if head.startswith(GZIP_MAGIC):
            self._kind = "gzip"
            self._dec = zlib.decompressobj(31)  # wbits=31 -> gzip
        elif head.startswith(XZ_MAGIC):
            self._kind = "xz"
            self._dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        elif head.startswith(BZ2_MAGIC):
            self._kind = "bz2"
            self._dec = bz2.BZ2Decompressor()
        self._members = 1

    def _new_member(self, unused: bytes) -> None:
        """Chain the next concatenated compression member/stream."""

        if self._kind == "gzip":
            self._dec = zlib.decompressobj(31)
        elif self._kind == "xz":
            self._dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        else:  # bz2
            self._dec = bz2.BZ2Decompressor()
        self._members += 1
        self._pending = unused

    # -------------------------------------------------------------- pumping
    def _pump(self) -> None:
        """Move one raw chunk through the decompressor into the output buf."""

        if self._raw_eof:
            return

        if self._kind == "plain":
            if self._pending:
                chunk, self._pending = self._pending, b""
            else:
                chunk = self._raw.read(READ_CHUNK_SIZE)
            if not chunk:
                self._raw_eof = True
                self._stream_ok = True
                return
            self._buf.extend(chunk)
            return

        if self._pending:
            chunk, self._pending = self._pending, b""
        else:
            chunk = self._raw.read(READ_CHUNK_SIZE)
            if not chunk:
                self._raw_eof = True
                self._finish_at_eof()
                return

        try:
            out = self._dec.decompress(chunk)
        except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError) as exc:
            # zlib/lzma/bz2 verify CRC and length checks here.
            raise LayerStreamError(
                "checksum",
                f"{self._kind} 成员 {self._members} 解压校验失败：{exc}",
            ) from exc
        if out:
            self._buf.extend(out)

        if self._dec.eof:
            unused = self._dec.unused_data
            if unused:
                # Concatenated member: its first bytes are already inside
                # ``unused``; the boundary may sit inside a tar header/body.
                self._new_member(unused)
                self._pump()

    def _finish_at_eof(self) -> None:
        """Validate end state once every raw byte has been consumed."""

        if not self._dec.eof:
            raise LayerStreamError(
                "truncated",
                f"{self._kind} 成员 {self._members} 未正常结束："
                "压缩流尾部缺失或数据被截断",
            )
        unused = self._dec.unused_data
        if unused:
            # Another member began but the raw stream ended underneath it.
            self._new_member(unused)
            self._finish_at_eof()
            return
        self._stream_ok = True

    # ------------------------------------------------------------------ read
    def read(self, size=-1):
        if size is None or size < 0:
            parts: list[bytes] = []
            while True:
                part = self.read(READ_CHUNK_SIZE)
                if not part:
                    return b"".join(parts)
                parts.append(part)
        if size == 0:
            return b""
        while len(self._buf) < size and not self._raw_eof:
            self._pump()
        if not self._buf:
            return b""
        out = bytes(self._buf[:size])
        del self._buf[:size]
        return out

    # ------------------------------------------------------------- finalize
    def drain_and_verify(self) -> None:
        """Consume everything after the tar end-of-archive marker.

        Valid tar padding is a sequence of zero blocks; any non-zero trailing
        byte means the layer carries data the tar format does not account for
        and must be rejected.  Also asserts that every compressed member ended
        with a valid trailer and checksum.
        """

        tail = bytearray()
        while True:
            chunk = self.read(READ_CHUNK_SIZE)
            if not chunk:
                break
            tail.extend(chunk)

        if any(tail):
            nonzero = sum(1 for byte in tail if byte != 0)
            raise LayerStreamError(
                "trailing",
                "tar 结束标记之后存在 "
                f"{len(tail)} 字节数据（其中 {nonzero} 字节非零），拒绝放行该层",
            )

        if self._kind != "plain" and not self._stream_ok:
            raise LayerStreamError(
                "truncated",
                f"{self._kind} 压缩流未到达合法结束状态（共 {self._members} 个成员）",
            )
