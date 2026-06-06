"""Carrier adapter registry and safe dispatch helpers."""

from __future__ import annotations

from .base import (
    CapacityEstimate,
    CarrierAdapter,
    CarrierAdapterError,
    CarrierDetection,
    CarrierError,
    CarrierExtraction,
    CarrierOutput,
    CarrierRegistryError,
    CarrierUnsupportedError,
    PayloadKind,
    coerce_bytes,
    ensure_carrier_bytes_within_limit,
    ensure_extracted_payload_within_limit,
)
from .png import PngLosslessCarrierAdapter


def builtin_adapters() -> dict[str, CarrierAdapter]:
    adapter = PngLosslessCarrierAdapter()
    return {adapter.kind: adapter}


_ADAPTERS: dict[str, CarrierAdapter] = builtin_adapters()


def _normalize_kind(kind: str | None) -> str:
    if not isinstance(kind, str) or not kind.strip():
        raise CarrierUnsupportedError()
    return kind.strip()


def registered_kinds() -> tuple[str, ...]:
    return tuple(sorted(_ADAPTERS))


def register_adapter(adapter: CarrierAdapter) -> CarrierAdapter:
    kind = _normalize_kind(getattr(adapter, "kind", None))
    if kind in _ADAPTERS:
        raise CarrierRegistryError()
    _ADAPTERS[kind] = adapter
    return adapter


def get_adapter(kind: str) -> CarrierAdapter:
    normalized = _normalize_kind(kind)
    adapter = _ADAPTERS.get(normalized)
    if adapter is None:
        raise CarrierUnsupportedError()
    return adapter


def detect_carrier(
    carrier_bytes: bytes | bytearray | memoryview,
    *,
    filename: str | None = None,
    mime_type: str | None = None,
) -> CarrierDetection | None:
    data = coerce_bytes(carrier_bytes)
    ensure_carrier_bytes_within_limit(data)

    for adapter in tuple(_ADAPTERS.values()):
        try:
            detection = adapter.detect(data, filename=filename, mime_type=mime_type)
        except CarrierError:
            raise
        except Exception as exc:
            raise CarrierAdapterError() from exc
        if detection is None:
            continue
        if detection.kind != adapter.kind:
            raise CarrierAdapterError()
        return detection
    return None


def estimate_capacity(
    kind: str,
    carrier_bytes: bytes | bytearray | memoryview | None = None,
    *,
    payload_size: int = 0,
) -> CapacityEstimate:
    if payload_size < 0:
        raise CarrierError("carrier_invalid_payload_size")
    data = None
    if carrier_bytes is not None:
        data = coerce_bytes(carrier_bytes)
        ensure_carrier_bytes_within_limit(data)

    adapter = get_adapter(kind)
    try:
        estimate = adapter.estimate_capacity(data, payload_size=payload_size)
    except CarrierError:
        raise
    except Exception as exc:
        raise CarrierAdapterError() from exc
    if estimate.kind != adapter.kind:
        raise CarrierAdapterError()
    return estimate


def embed_envelope(
    kind: str,
    envelope_bytes: bytes | bytearray | memoryview,
    *,
    carrier_bytes: bytes | bytearray | memoryview | None = None,
    payload_kind: PayloadKind = "message",
) -> CarrierOutput:
    data = coerce_bytes(envelope_bytes)
    ensure_extracted_payload_within_limit(data, payload_kind)
    carrier_data = None
    if carrier_bytes is not None:
        carrier_data = coerce_bytes(carrier_bytes)
        ensure_carrier_bytes_within_limit(carrier_data)

    adapter = get_adapter(kind)
    try:
        output = adapter.embed(data, carrier_bytes=carrier_data, payload_kind=payload_kind)
    except CarrierError:
        raise
    except Exception as exc:
        raise CarrierAdapterError() from exc
    if output.kind != adapter.kind:
        raise CarrierAdapterError()
    ensure_carrier_bytes_within_limit(output.carrier_bytes)
    return output


def extract_envelope(
    kind: str,
    carrier_bytes: bytes | bytearray | memoryview,
    *,
    payload_kind: PayloadKind = "message",
) -> CarrierExtraction:
    data = coerce_bytes(carrier_bytes)
    ensure_carrier_bytes_within_limit(data)

    adapter = get_adapter(kind)
    try:
        extracted = adapter.extract(data, payload_kind=payload_kind)
    except CarrierError:
        raise
    except Exception as exc:
        raise CarrierAdapterError() from exc

    if isinstance(extracted, CarrierExtraction):
        result = extracted
    else:
        result = CarrierExtraction(kind=adapter.kind, envelope_bytes=coerce_bytes(extracted))
    if result.kind != adapter.kind:
        raise CarrierAdapterError()
    ensure_extracted_payload_within_limit(result.envelope_bytes, payload_kind)
    return result
