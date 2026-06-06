import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.carrier import (  # noqa: E402
    CARRIER_PUBLIC_ERROR,
    PLANNED_CARRIER_KINDS,
    PNG_LOSSLESS_V1,
    QR_MATRIX_V1,
    SUPPORTED_CARRIER_KINDS,
    CapacityEstimate,
    CarrierAdapterError,
    CarrierDetection,
    CarrierExtraction,
    CarrierLimitError,
    CarrierOutput,
    CarrierRegistryError,
    CarrierUnsupportedError,
)
from core.carrier import base as carrier_base  # noqa: E402
from core.carrier import registry as carrier_registry  # noqa: E402


@pytest.fixture(autouse=True)
def empty_carrier_registry(monkeypatch):
    monkeypatch.setattr(carrier_registry, "_ADAPTERS", {})


def _assert_generic_error(exc_info, *sentinels):
    message = str(exc_info.value)
    assert message == CARRIER_PUBLIC_ERROR
    for sentinel in sentinels:
        assert sentinel not in message


class FakeCarrierAdapter:
    kind = "fake_v1"

    def __init__(self, extracted=b"PARC-message"):
        self.calls = []
        self.extracted = extracted

    def detect(self, carrier_bytes, *, filename=None, mime_type=None):
        self.calls.append(("detect", carrier_bytes, filename, mime_type))
        if carrier_bytes.startswith(b"FAKE"):
            return CarrierDetection(kind=self.kind)
        return None

    def estimate_capacity(self, carrier_bytes=None, *, payload_size=0):
        self.calls.append(("estimate", carrier_bytes, payload_size))
        capacity = 256
        return CapacityEstimate(
            kind=self.kind,
            capacity_bytes=capacity,
            payload_bytes=payload_size,
            fits=payload_size <= capacity,
        )

    def embed(self, envelope_bytes, *, carrier_bytes=None, payload_kind="message"):
        self.calls.append(("embed", envelope_bytes, carrier_bytes, payload_kind))
        return CarrierOutput(
            kind=self.kind,
            carrier_bytes=b"FAKE" + envelope_bytes,
            filename="carrier.fake",
            mime_type="application/octet-stream",
        )

    def extract(self, carrier_bytes, *, payload_kind="message"):
        self.calls.append(("extract", carrier_bytes, payload_kind))
        return CarrierExtraction(kind=self.kind, envelope_bytes=self.extracted)


class RaisingCarrierAdapter:
    kind = "raising_v1"

    def detect(self, carrier_bytes, *, filename=None, mime_type=None):
        raise RuntimeError("payload-secret-sentinel path-secret-sentinel token-secret-sentinel")

    def estimate_capacity(self, carrier_bytes=None, *, payload_size=0):
        raise RuntimeError("payload-secret-sentinel path-secret-sentinel token-secret-sentinel")

    def embed(self, envelope_bytes, *, carrier_bytes=None, payload_kind="message"):
        raise RuntimeError("payload-secret-sentinel path-secret-sentinel token-secret-sentinel")

    def extract(self, carrier_bytes, *, payload_kind="message"):
        raise RuntimeError("payload-secret-sentinel path-secret-sentinel token-secret-sentinel")


def test_registry_can_be_isolated_for_adapter_stubs():
    assert carrier_registry.registered_kinds() == ()
    assert carrier_registry.detect_carrier(b"not a carrier") is None


def test_kind_constants_separate_supported_and_planned_carriers():
    assert SUPPORTED_CARRIER_KINDS == (PNG_LOSSLESS_V1,)
    assert PLANNED_CARRIER_KINDS == (QR_MATRIX_V1,)

    for kind in PLANNED_CARRIER_KINDS:
        with pytest.raises(CarrierUnsupportedError) as get_exc:
            carrier_registry.get_adapter(kind)
        _assert_generic_error(get_exc, kind)

        with pytest.raises(CarrierUnsupportedError) as estimate_exc:
            carrier_registry.estimate_capacity(kind, payload_size=8)
        _assert_generic_error(estimate_exc, kind)

        with pytest.raises(CarrierUnsupportedError) as embed_exc:
            carrier_registry.embed_envelope(kind, b"PARC")
        _assert_generic_error(embed_exc, kind)

        with pytest.raises(CarrierUnsupportedError) as extract_exc:
            carrier_registry.extract_envelope(kind, b"carrier")
        _assert_generic_error(extract_exc, kind)


def test_registry_rejects_duplicate_adapter_kind():
    carrier_registry.register_adapter(FakeCarrierAdapter())

    with pytest.raises(CarrierRegistryError) as exc_info:
        carrier_registry.register_adapter(FakeCarrierAdapter())

    _assert_generic_error(exc_info, "fake_v1")


def test_fake_adapter_dispatch_round_trip():
    adapter = carrier_registry.register_adapter(FakeCarrierAdapter())

    detection = carrier_registry.detect_carrier(
        b"FAKE carrier",
        filename="carrier.fake",
        mime_type="application/octet-stream",
    )
    assert detection == CarrierDetection(kind="fake_v1")

    estimate = carrier_registry.estimate_capacity("fake_v1", payload_size=128)
    assert estimate.fits is True
    assert estimate.capacity_bytes == 256

    output = carrier_registry.embed_envelope("fake_v1", b"PARC-message")
    assert output.carrier_bytes == b"FAKEPARC-message"

    extracted = carrier_registry.extract_envelope("fake_v1", b"FAKEPARC-message")
    assert extracted == CarrierExtraction(kind="fake_v1", envelope_bytes=b"PARC-message")
    assert [call[0] for call in adapter.calls] == ["detect", "estimate", "embed", "extract"]
    assert adapter.calls[2] == ("embed", b"PARC-message", None, "message")


def test_carrier_input_limit_rejects_before_adapter_work(monkeypatch):
    adapter = FakeCarrierAdapter()
    carrier_registry.register_adapter(adapter)
    sentinel = b"payload-secret-sentinel"
    monkeypatch.setattr(carrier_base, "MAX_CARRIER_FILE_BYTES", 8)

    with pytest.raises(CarrierLimitError) as exc_info:
        carrier_registry.detect_carrier(b"FAKE" + sentinel)

    _assert_generic_error(exc_info, sentinel.decode("ascii"))
    assert adapter.calls == []


def test_extract_limit_rejects_adapter_payload_without_reflection(monkeypatch):
    sentinel = b"payload-secret-sentinel"
    adapter = FakeCarrierAdapter(extracted=b"PARC" + sentinel)
    carrier_registry.register_adapter(adapter)
    monkeypatch.setattr(carrier_base, "MAX_EXTRACTED_MESSAGE_BYTES", 8)

    with pytest.raises(CarrierLimitError) as exc_info:
        carrier_registry.extract_envelope("fake_v1", b"FAKE carrier")

    _assert_generic_error(exc_info, sentinel.decode("ascii"))
    assert [call[0] for call in adapter.calls] == ["extract"]


def test_embed_limit_rejects_payload_before_adapter_work(monkeypatch):
    adapter = FakeCarrierAdapter()
    carrier_registry.register_adapter(adapter)
    sentinel = b"payload-secret-sentinel"
    monkeypatch.setattr(carrier_base, "MAX_EXTRACTED_SETUP_BYTES", 8)

    with pytest.raises(CarrierLimitError) as exc_info:
        carrier_registry.embed_envelope("fake_v1", b"PARC" + sentinel, payload_kind="setup")

    _assert_generic_error(exc_info, sentinel.decode("ascii"))
    assert adapter.calls == []


def test_adapter_exceptions_are_generic_and_do_not_reflect_sensitive_inputs():
    carrier_registry.register_adapter(RaisingCarrierAdapter())
    sentinels = (
        "payload-secret-sentinel",
        "path-secret-sentinel",
        "token-secret-sentinel",
    )

    with pytest.raises(CarrierAdapterError) as detect_exc:
        carrier_registry.detect_carrier(
            b"payload-secret-sentinel",
            filename="path-secret-sentinel",
            mime_type="application/octet-stream",
        )
    _assert_generic_error(detect_exc, *sentinels)

    with pytest.raises(CarrierAdapterError) as estimate_exc:
        carrier_registry.estimate_capacity("raising_v1", b"token-secret-sentinel")
    _assert_generic_error(estimate_exc, *sentinels)

    with pytest.raises(CarrierAdapterError) as embed_exc:
        carrier_registry.embed_envelope("raising_v1", b"payload-secret-sentinel")
    _assert_generic_error(embed_exc, *sentinels)

    with pytest.raises(CarrierAdapterError) as extract_exc:
        carrier_registry.extract_envelope("raising_v1", b"path-secret-sentinel")
    _assert_generic_error(extract_exc, *sentinels)
