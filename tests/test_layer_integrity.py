"""Integrity validation for compressed and concatenated image layers.

These tests prove that a layer is only accepted when its whole compressed
stream has been read with valid end state and checksum, that concatenated gzip
members are treated as one decompressed byte stream, that bytes after the tar
end-of-archive marker are checked, and that the HTTP layer reports the failing
layer number with HTTP 400.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import tarfile
import unittest

from app.layerio import LayerStreamError, ValidatingLayerReader
from app.merger import ScanError, scan_docker_archive

from tests.test_merger import make_archive, make_layer, scan


def privileged_layer() -> bytes:
    return make_layer([{"name": "bin/suid-tool", "mode": 0o4755, "data": b"abc"}])


def corrupt_middle(payload: bytearray | bytes, *, offset: int = 20) -> bytes:
    blob = bytearray(payload)
    blob[offset] ^= 0xFF
    return bytes(blob)


def split_gzip(tar_bytes: bytes, split: int = 300) -> bytes:
    """Two gzip members whose boundary lies inside a tar header."""

    return gzip.compress(tar_bytes[:split]) + gzip.compress(tar_bytes[split:])


class ReaderUnitTests(unittest.TestCase):
    def _tar_names(self, payload: bytes) -> list[str]:
        reader = ValidatingLayerReader(io.BytesIO(payload))
        with tarfile.open(fileobj=reader, mode="r|") as tf:
            names = [member.name for member in tf]
        reader.drain_and_verify()
        return names

    def test_plain_tar_still_uses_same_reader(self):
        tar_bytes = privileged_layer()
        reader = ValidatingLayerReader(io.BytesIO(tar_bytes))
        self.assertEqual(reader.kind, "plain")
        self.assertEqual(self._tar_names(tar_bytes), ["bin/suid-tool"])

    def test_empty_blob_is_rejected_as_tar_error_not_accepted(self):
        with self.assertRaises(tarfile.TarError):
            self._tar_names(b"")

    def test_gzip_split_member_boundary_in_header_is_one_stream(self):
        tar_bytes = privileged_layer()
        payload = split_gzip(tar_bytes, split=120)
        reader = ValidatingLayerReader(io.BytesIO(payload))
        with tarfile.open(fileobj=reader, mode="r|") as tf:
            names = [member.name for member in tf]
        reader.drain_and_verify()
        self.assertEqual(names, ["bin/suid-tool"])
        self.assertEqual(reader.kind, "gzip")
        self.assertEqual(reader.member_count, 2)

    def test_gzip_split_inside_file_body_is_one_stream(self):
        big = make_layer(
            [{"name": "big", "mode": 0o4755, "data": os.urandom(20000)}]
        )
        split = 5000
        payload = gzip.compress(big[:split]) + gzip.compress(big[split:])
        self.assertEqual(self._tar_names(payload), ["big"])

    def test_three_gzip_members_all_validated(self):
        tar_bytes = privileged_layer()
        payload = (
            gzip.compress(tar_bytes[:50])
            + gzip.compress(tar_bytes[50:200])
            + gzip.compress(tar_bytes[200:])
        )
        self.assertEqual(self._tar_names(payload), ["bin/suid-tool"])

    def test_gzip_missing_trailer_is_rejected(self):
        payload = gzip.compress(privileged_layer())[:-8]
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(payload)
        self.assertEqual(caught.exception.category, "truncated")

    def test_gzip_bad_crc_is_rejected(self):
        payload = bytearray(gzip.compress(privileged_layer()))
        payload[-8] ^= 0x01  # flip a CRC byte
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(payload)
        self.assertEqual(caught.exception.category, "checksum")

    def test_gzip_bad_isize_is_rejected(self):
        payload = bytearray(gzip.compress(privileged_layer()))
        payload[-1] ^= 0x01  # flip the ISIZE trailer byte
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(payload)
        self.assertEqual(caught.exception.category, "checksum")

    def test_gzip_truncated_mid_stream_is_rejected(self):
        payload = gzip.compress(privileged_layer())
        with self.assertRaises(LayerStreamError):
            self._tar_names(payload[: len(payload) // 2])

    def test_second_gzip_member_truncated_is_rejected(self):
        tar_bytes = privileged_layer()
        payload = split_gzip(tar_bytes)[:-8]
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(payload)
        self.assertEqual(caught.exception.category, "truncated")
        self.assertIn("成员 2", caught.exception.message)

    def test_second_gzip_member_bad_crc_is_rejected(self):
        tar_bytes = privileged_layer()
        payload = bytearray(split_gzip(tar_bytes))
        payload[-8] ^= 0x01
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(bytes(payload))
        self.assertEqual(caught.exception.category, "checksum")

    def test_xz_valid_and_concatenated(self):
        tar_bytes = privileged_layer()
        payload = lzma.compress(tar_bytes, format=lzma.FORMAT_XZ)
        self.assertEqual(self._tar_names(payload), ["bin/suid-tool"])
        split = 200
        concat = (
            lzma.compress(tar_bytes[:split], format=lzma.FORMAT_XZ)
            + lzma.compress(tar_bytes[split:], format=lzma.FORMAT_XZ)
        )
        self.assertEqual(self._tar_names(concat), ["bin/suid-tool"])

    def test_xz_truncated_and_corrupt_are_rejected(self):
        payload = lzma.compress(privileged_layer(), format=lzma.FORMAT_XZ)
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(payload[:-12])
        self.assertEqual(caught.exception.category, "truncated")
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(corrupt_middle(payload))
        self.assertEqual(caught.exception.category, "checksum")

    def test_bz2_valid_and_concatenated(self):
        tar_bytes = privileged_layer()
        payload = bz2.compress(tar_bytes)
        self.assertEqual(self._tar_names(payload), ["bin/suid-tool"])
        split = 200
        concat = bz2.compress(tar_bytes[:split]) + bz2.compress(tar_bytes[split:])
        self.assertEqual(self._tar_names(concat), ["bin/suid-tool"])

    def test_bz2_truncated_and_corrupt_are_rejected(self):
        payload = bz2.compress(privileged_layer())
        with self.assertRaises(LayerStreamError):
            self._tar_names(payload[:-12])
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(corrupt_middle(payload))
        self.assertEqual(caught.exception.category, "checksum")

    def test_nonzero_bytes_after_tar_end_are_rejected(self):
        tar_bytes = privileged_layer()
        for label, payload in [
            ("plain", tar_bytes + b"GARBAGE"),
            ("gzip", gzip.compress(tar_bytes + b"GARBAGE")),
            ("bz2", bz2.compress(tar_bytes + b"GARBAGE")),
        ]:
            with self.subTest(label):
                with self.assertRaises(LayerStreamError) as caught:
                    self._tar_names(payload)
                self.assertEqual(caught.exception.category, "trailing")

    def test_zero_padding_after_tar_end_is_accepted(self):
        tar_bytes = privileged_layer()
        self.assertEqual(self._tar_names(tar_bytes + b"\x00" * 2048), ["bin/suid-tool"])
        self.assertEqual(
            self._tar_names(gzip.compress(tar_bytes + b"\x00" * 1024)),
            ["bin/suid-tool"],
        )

    def test_extra_gzip_member_with_second_tar_is_rejected(self):
        tar_bytes = privileged_layer()
        payload = gzip.compress(tar_bytes) + gzip.compress(tar_bytes)
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(payload)
        self.assertEqual(caught.exception.category, "trailing")

    def test_gzip_next_member_header_truncated_is_rejected(self):
        tar_bytes = privileged_layer()
        # A complete first member followed by only three bytes of the next
        # member header must not be silently accepted.
        payload = gzip.compress(tar_bytes) + b"\x1f\x8b\x08"
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(payload)
        self.assertEqual(caught.exception.category, "truncated")

    def test_junk_between_gzip_members_is_rejected(self):
        tar_bytes = privileged_layer()
        payload = (
            gzip.compress(tar_bytes[:200])
            + b"JUNK"
            + gzip.compress(tar_bytes[200:])
        )
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(payload)
        self.assertEqual(caught.exception.category, "checksum")

    def test_concatenated_xz_and_bz2_second_stream_damage_is_rejected(self):
        tar_bytes = privileged_layer()
        xz_concat = (
            lzma.compress(tar_bytes[:200], format=lzma.FORMAT_XZ)
            + lzma.compress(tar_bytes[200:], format=lzma.FORMAT_XZ)
        )
        damaged = bytearray(xz_concat)
        damaged[-15] ^= 0xFF
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(bytes(damaged))
        self.assertEqual(caught.exception.category, "checksum")

        bz2_concat = bz2.compress(tar_bytes[:200]) + bz2.compress(tar_bytes[200:])
        with self.assertRaises(LayerStreamError) as caught:
            self._tar_names(bz2_concat[:-8])
        self.assertEqual(caught.exception.category, "truncated")

    def test_reading_never_buffers_more_than_chunks(self):
        # A large layer must scan while the reader holds only small buffers.
        big = make_layer(
            [{"name": "big", "mode": 0o0755, "data": os.urandom(2 * 1024 * 1024)}]
        )
        reader = ValidatingLayerReader(io.BytesIO(gzip.compress(big)))
        max_held = 0
        with tarfile.open(fileobj=reader, mode="r|") as tf:
            for _ in tf:
                max_held = max(max_held, len(reader._buf))
        reader.drain_and_verify()
        self.assertLess(max_held, 256 * 1024)


class ScannerIntegrationTests(unittest.TestCase):
    def test_valid_compressed_formats_scan_identically(self):
        tar_bytes = privileged_layer()
        for label, payload in [
            ("plain", tar_bytes),
            ("gzip", gzip.compress(tar_bytes)),
            ("concat-gzip", split_gzip(tar_bytes)),
            ("xz", lzma.compress(tar_bytes, format=lzma.FORMAT_XZ)),
            ("bz2", bz2.compress(tar_bytes)),
        ]:
            with self.subTest(label):
                result = scan([payload])
                self.assertEqual(
                    [item["path"] for item in result.files], ["/bin/suid-tool"]
                )

    def _assert_layer_failure(self, layers, *, layer_number, code):
        with self.assertRaises(ScanError) as caught:
            scan(layers)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(caught.exception.layer_number, layer_number)

    def test_truncated_gzip_fails_with_layer_number(self):
        good = privileged_layer()
        bad = gzip.compress(good)[:-8]
        self._assert_layer_failure(
            [good, bad], layer_number=2, code="layer_compression_truncated"
        )

    def test_bad_crc_gzip_fails_with_layer_number(self):
        good = bytearray(gzip.compress(privileged_layer()))
        good[-8] ^= 0x01
        self._assert_layer_failure(
            [bytes(good)], layer_number=1, code="layer_compression_corrupt"
        )

    def test_corrupt_xz_and_bz2_fail(self):
        tar_bytes = privileged_layer()
        xz_bad = corrupt_middle(
            lzma.compress(tar_bytes, format=lzma.FORMAT_XZ), offset=30
        )
        self._assert_layer_failure(
            [xz_bad], layer_number=1, code="layer_compression_corrupt"
        )
        bz2_bad = bz2.compress(tar_bytes)[:-10]
        self._assert_layer_failure(
            [bz2_bad], layer_number=1, code="layer_compression_truncated"
        )

    def test_trailing_data_fails_with_layer_number(self):
        bad = gzip.compress(privileged_layer() + b"X")
        self._assert_layer_failure(
            [privileged_layer(), bad],
            layer_number=2,
            code="layer_tail_invalid",
        )

    def test_later_layer_failure_returns_no_partial_results(self):
        good = make_layer([{"name": "lower-suid", "mode": 0o4755}])
        bad = gzip.compress(privileged_layer())[:-8]
        with self.assertRaises(ScanError):
            scan([good, bad])
        # And a subsequent valid upload still scans normally.
        result = scan([good, privileged_layer()])
        self.assertEqual(len(result.files), 2)

    def test_concat_gzip_boundary_in_header_scans(self):
        tar_bytes = privileged_layer()
        result = scan([split_gzip(tar_bytes, split=120)])
        self.assertEqual(result.files[0]["path"], "/bin/suid-tool")

    def test_demo_archive_layers_are_all_validated(self):
        from app.sample import build_demo_archive

        result = scan_docker_archive(
            io.BytesIO(build_demo_archive())
        ).as_dict(source="demo")
        self.assertEqual(result["summary"]["layers_scanned"], 4)
        self.assertEqual(result["summary"]["privileged_files"], 5)


class HttpEndpointTests(unittest.TestCase):
    def _client(self):
        from fastapi.testclient import TestClient

        from app.main import app

        return TestClient(app)

    def test_corrupt_layer_returns_400_with_layer_number_and_reason(self):
        client = self._client()
        good = privileged_layer()
        bad = gzip.compress(good)[:-8]
        archive = make_archive([good, bad])
        for path in ("/api/scan", "/scan"):
            with self.subTest(path):
                response = client.post(
                    path,
                    files={"archive": ("image.tar", archive, "application/x-tar")},
                )
                self.assertEqual(response.status_code, 400)
                detail = response.json()["detail"]
                self.assertEqual(detail["layer_number"], 2)
                self.assertEqual(detail["code"], "layer_compression_truncated")
                self.assertTrue(detail["message"])

    def test_valid_upload_after_error_still_succeeds(self):
        client = self._client()
        bad = gzip.compress(privileged_layer())[:-8]
        bad_response = client.post(
            "/api/scan",
            files={"archive": ("bad.tar", make_archive([bad]), "application/x-tar")},
        )
        self.assertEqual(bad_response.status_code, 400)

        good_response = client.post(
            "/api/scan",
            files={
                "archive": (
                    "good.tar",
                    make_archive([privileged_layer()]),
                    "application/x-tar",
                )
            },
        )
        self.assertEqual(good_response.status_code, 200)
        self.assertEqual(
            good_response.json()["files"][0]["path"], "/bin/suid-tool"
        )

    def test_demo_endpoint_uses_same_validated_pipeline(self):
        client = self._client()
        response = client.get("/api/demo")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["summary"]["layers_scanned"], 4)


if __name__ == "__main__":
    unittest.main()
