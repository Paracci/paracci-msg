"""Shared carrier transport types and limits.

Carrier mode is an outer wrapper around existing Paracci files.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from core.ingest_limits import MAX_MESSAGE_ENVELOPE_BYTES, MAX_SETUP_FILE_BYTES
from core.sanitizer import MAX_IMAGE_DIMENSION, MAX_IMAGE_FRAMES, MAX_IMAGE_PIXELS


PayloadKind = Literal["setup", "message"]

PNG_LOSSLESS_V1 = "png_lossless_v1"
QR_MATRIX_V1 = "qr_matrix_v1"
SUPPORTED_CARRIER_KINDS = (PNG_LOSSLESS_V1,)
PLANNED_CARRIER_KINDS = (QR_MATRIX_V1,)

MAX_CARRIER_FILE_BYTES = MAX_MESSAGE_ENVELOPE_BYTES
MAX_EXTRACTED_SETUP_BYTES = MAX_SETUP_FILE_BYTES
MAX_EXTRACTED_MESSAGE_BYTES = MAX_MESSAGE_ENVELOPE_BYTES
MAX_CARRIER_IMAGE_PIXELS = MAX_IMAGE_PIXELS
MAX_CARRIER_IMAGE_DIMENSION = MAX_IMAGE_DIMENSION
MAX_CARRIER_IMAGE_FRAMES = MAX_IMAGE_FRAMES

CARRIER_PUBLIC_ERROR = "Carrier file could not be processed safely."


class CarrierError(ValueError):
    """Base class for public carrier failures.

    Stringifying carrier errors must stay generic because carrier inputs may be
    attacker-controlled files, filenames, paths, or embedded payload bytes.
    """

    code = "carrier_error"
    public_message = CARRIER_PUBLIC_ERROR

    def __init__(self, code: str | None = None):
        self.code = code or self.code
        super().__init__(self.public_message)


class CarrierLimitError(CarrierError):
    code = "carrier_limit"


class CarrierUnsupportedError(CarrierError):
    code = "carrier_unsupported"


class CarrierRegistryError(CarrierError):
    code = "carrier_registry_error"


class CarrierAdapterError(CarrierError):
    code = "carrier_adapter_error"


@dataclass(frozen=True)
class CarrierDetection:
    kind: str
    confidence: float = 1.0
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class CapacityEstimate:
    kind: str
    capacity_bytes: int
    payload_bytes: int = 0
    fits: bool = False
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class CarrierOutput:
    kind: str
    carrier_bytes: bytes
    filename: str
    mime_type: str
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class CarrierExtraction:
    kind: str
    envelope_bytes: bytes
    warnings: tuple[str, ...] = ()


class CarrierAdapter(Protocol):
    kind: str

    def detect(
        self,
        carrier_bytes: bytes,
        *,
        filename: str | None = None,
        mime_type: str | None = None,
    ) -> CarrierDetection | None:
        ...

    def estimate_capacity(
        self,
        carrier_bytes: bytes | None = None,
        *,
        payload_size: int = 0,
    ) -> CapacityEstimate:
        ...

    def embed(
        self,
        envelope_bytes: bytes,
        *,
        carrier_bytes: bytes | None = None,
        payload_kind: PayloadKind = "message",
    ) -> CarrierOutput:
        ...

    def extract(
        self,
        carrier_bytes: bytes,
        *,
        payload_kind: PayloadKind = "message",
    ) -> bytes | CarrierExtraction:
        ...


def coerce_bytes(value: bytes | bytearray | memoryview) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    raise CarrierError("carrier_invalid_input")


def ensure_carrier_bytes_within_limit(carrier_bytes: bytes) -> None:
    if len(carrier_bytes) > MAX_CARRIER_FILE_BYTES:
        raise CarrierLimitError()


def extracted_payload_limit(payload_kind: PayloadKind) -> int:
    if payload_kind == "setup":
        return MAX_EXTRACTED_SETUP_BYTES
    if payload_kind == "message":
        return MAX_EXTRACTED_MESSAGE_BYTES
    raise CarrierError("carrier_invalid_payload_kind")


def ensure_extracted_payload_within_limit(
    envelope_bytes: bytes,
    payload_kind: PayloadKind,
) -> None:
    if len(envelope_bytes) > extracted_payload_limit(payload_kind):
        raise CarrierLimitError()
