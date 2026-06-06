"""Lossless PNG carrier adapter."""

from __future__ import annotations

import io
import struct
import warnings
import zlib

from PIL import Image, UnidentifiedImageError

from core.sanitizer import ImageSafetyError, _validate_image_metadata

from .base import (
    PNG_LOSSLESS_V1,
    CapacityEstimate,
    CarrierAdapterError,
    CarrierDetection,
    CarrierExtraction,
    CarrierLimitError,
    CarrierOutput,
    PayloadKind,
    coerce_bytes,
    ensure_extracted_payload_within_limit,
    extracted_payload_limit,
)


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_CONTAINER_MAGIC = b"PARACCI_PNG_LSB1"
PNG_CONTAINER_HEADER = struct.Struct(">16sQI")
PNG_CONTAINER_HEADER_BYTES = PNG_CONTAINER_HEADER.size
SAFE_SOURCE_PNG_MODES = frozenset({"1", "L", "LA", "P", "RGB", "RGBA"})


class PngLosslessCarrierAdapter:
    kind = PNG_LOSSLESS_V1

    def detect(
        self,
        carrier_bytes: bytes,
        *,
        filename: str | None = None,
        mime_type: str | None = None,
    ) -> CarrierDetection | None:
        if not _has_png_signature(carrier_bytes):
            return None
        image = _load_png_as_rgb_or_rgba(carrier_bytes)
        if _capacity_for_image(image) < PNG_CONTAINER_HEADER_BYTES:
            return None
        header = _extract_hidden_bytes(image, PNG_CONTAINER_HEADER_BYTES)
        try:
            magic, payload_length, _checksum = PNG_CONTAINER_HEADER.unpack(header)
        except struct.error as exc:
            raise CarrierAdapterError() from exc
        if magic != PNG_CONTAINER_MAGIC:
            return None
        if payload_length > _capacity_for_image(image):
            raise CarrierAdapterError()
        return CarrierDetection(kind=self.kind)

    def estimate_capacity(
        self,
        carrier_bytes: bytes | None = None,
        *,
        payload_size: int = 0,
    ) -> CapacityEstimate:
        if carrier_bytes is None:
            raise CarrierAdapterError()
        image = _load_png_as_rgb_or_rgba(carrier_bytes)
        capacity = _capacity_for_image(image)
        return CapacityEstimate(
            kind=self.kind,
            capacity_bytes=capacity,
            payload_bytes=payload_size,
            fits=payload_size <= capacity,
        )

    def embed(
        self,
        envelope_bytes: bytes,
        *,
        carrier_bytes: bytes | None = None,
        payload_kind: PayloadKind = "message",
    ) -> CarrierOutput:
        if carrier_bytes is None:
            raise CarrierAdapterError()
        ensure_extracted_payload_within_limit(envelope_bytes, payload_kind)
        image = _load_png_as_rgb_or_rgba(carrier_bytes)
        capacity = _capacity_for_image(image)
        if len(envelope_bytes) > capacity:
            raise CarrierLimitError()

        carrier_image = _embed_hidden_bytes(image, _build_container(envelope_bytes))
        output = io.BytesIO()
        carrier_image.save(output, format="PNG", optimize=True)
        return CarrierOutput(
            kind=self.kind,
            carrier_bytes=output.getvalue(),
            filename="carrier.png",
            mime_type="image/png",
        )

    def extract(
        self,
        carrier_bytes: bytes,
        *,
        payload_kind: PayloadKind = "message",
    ) -> CarrierExtraction:
        image = _load_png_as_rgb_or_rgba(carrier_bytes)
        capacity = _capacity_for_image(image)
        if capacity < PNG_CONTAINER_HEADER_BYTES:
            raise CarrierAdapterError()

        header = _extract_hidden_bytes(image, PNG_CONTAINER_HEADER_BYTES)
        try:
            magic, payload_length, expected_crc = PNG_CONTAINER_HEADER.unpack(header)
        except struct.error as exc:
            raise CarrierAdapterError() from exc
        if magic != PNG_CONTAINER_MAGIC:
            raise CarrierAdapterError()
        if payload_length > extracted_payload_limit(payload_kind):
            raise CarrierLimitError()
        if payload_length > capacity:
            raise CarrierAdapterError()

        payload = _extract_hidden_bytes(
            image,
            PNG_CONTAINER_HEADER_BYTES + payload_length,
        )[PNG_CONTAINER_HEADER_BYTES:]
        if _crc32(payload) != expected_crc:
            raise CarrierAdapterError()
        ensure_extracted_payload_within_limit(payload, payload_kind)
        return CarrierExtraction(kind=self.kind, envelope_bytes=payload)


def _has_png_signature(data: bytes) -> bool:
    return data.startswith(PNG_SIGNATURE)


def _load_png_as_rgb_or_rgba(data: bytes) -> Image.Image:
    if not _has_png_signature(data):
        raise CarrierAdapterError()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                if image.format != "PNG":
                    raise CarrierAdapterError()
                _validate_image_metadata(image)
                if image.mode not in SAFE_SOURCE_PNG_MODES:
                    raise CarrierAdapterError()
                image.load()
                has_alpha = image.mode in ("RGBA", "LA") or (
                    image.mode == "P" and "transparency" in image.info
                )
                return image.convert("RGBA" if has_alpha else "RGB")
    except (
        ImageSafetyError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        OSError,
        ValueError,
        KeyError,
    ) as exc:
        raise CarrierAdapterError() from exc


def _capacity_for_image(image: Image.Image) -> int:
    width, height = image.size
    usable_bits = width * height * 3
    usable_bytes = usable_bits // 8
    return max(0, usable_bytes - PNG_CONTAINER_HEADER_BYTES)


def _build_container(payload: bytes) -> bytes:
    return PNG_CONTAINER_HEADER.pack(
        PNG_CONTAINER_MAGIC,
        len(payload),
        _crc32(payload),
    ) + payload


def _embed_hidden_bytes(image: Image.Image, hidden_bytes: bytes) -> Image.Image:
    if len(hidden_bytes) > _capacity_for_image(image) + PNG_CONTAINER_HEADER_BYTES:
        raise CarrierLimitError()
    channel_count = len(image.getbands())
    data = bytearray(image.tobytes())
    for bit_index, bit in enumerate(_iter_bits(hidden_bytes)):
        pixel_index, channel_index = divmod(bit_index, 3)
        offset = pixel_index * channel_count + channel_index
        data[offset] = (data[offset] & 0xFE) | bit
    return Image.frombytes(image.mode, image.size, bytes(data))


def _extract_hidden_bytes(image: Image.Image, byte_count: int) -> bytes:
    if byte_count < 0:
        raise CarrierAdapterError()
    required_bits = byte_count * 8
    if required_bits > image.width * image.height * 3:
        raise CarrierAdapterError()

    channel_count = len(image.getbands())
    data = image.tobytes()
    output = bytearray()
    current = 0
    used_bits = 0
    for bit_index in range(required_bits):
        pixel_index, channel_index = divmod(bit_index, 3)
        offset = pixel_index * channel_count + channel_index
        current = (current << 1) | (data[offset] & 0x01)
        used_bits += 1
        if used_bits == 8:
            output.append(current)
            current = 0
            used_bits = 0
    return bytes(output)


def _iter_bits(data: bytes):
    for value in data:
        for shift in range(7, -1, -1):
            yield (value >> shift) & 0x01


def _crc32(data: bytes) -> int:
    return zlib.crc32(coerce_bytes(data)) & 0xFFFFFFFF
