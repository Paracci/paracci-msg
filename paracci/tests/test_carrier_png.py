import io
import struct
import sys
import zlib
from pathlib import Path

import pytest
from PIL import Image, PngImagePlugin

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.carrier import (  # noqa: E402
    CARRIER_PUBLIC_ERROR,
    PNG_LOSSLESS_V1,
    QR_MATRIX_V1,
    CarrierAdapterError,
    CarrierError,
    CarrierLimitError,
    CarrierUnsupportedError,
    PngLosslessCarrierAdapter,
)
from core.carrier import base as carrier_base  # noqa: E402
from core.carrier import registry as carrier_registry  # noqa: E402
from core.carrier.png import (  # noqa: E402
    PNG_CONTAINER_HEADER_BYTES,
    PNG_CONTAINER_MAGIC,
    PNG_SIGNATURE,
)


@pytest.fixture(autouse=True)
def builtin_carrier_registry(monkeypatch):
    monkeypatch.setattr(carrier_registry, "_ADAPTERS", carrier_registry.builtin_adapters())


def _assert_generic_error(exc_info, *sentinels):
    message = str(exc_info.value)
    assert message == CARRIER_PUBLIC_ERROR
    for sentinel in sentinels:
        assert sentinel not in message


def _png_bytes(size=(64, 64), mode="RGB", color=None, pnginfo=None):
    if color is None:
        color = (32, 96, 160, 255) if "A" in mode else (32, 96, 160)
    output = io.BytesIO()
    Image.new(mode, size, color).save(output, format="PNG", pnginfo=pnginfo)
    return output.getvalue()


def _expected_capacity(width, height):
    return max(0, (width * height * 3) // 8 - PNG_CONTAINER_HEADER_BYTES)


def _png_metadata_bytes(width, height):
    def chunk(kind, data):
        crc = zlib.crc32(kind + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return PNG_SIGNATURE + chunk(b"IHDR", ihdr) + chunk(b"IEND", b"")


def _flip_hidden_bit(png_bytes, bit_index):
    with Image.open(io.BytesIO(png_bytes)) as image:
        image = image.convert("RGBA" if image.mode == "RGBA" else "RGB")
        channel_count = len(image.getbands())
        data = bytearray(image.tobytes())
        pixel_index, channel_index = divmod(bit_index, 3)
        offset = pixel_index * channel_count + channel_index
        data[offset] ^= 0x01
        mutated = Image.frombytes(image.mode, image.size, bytes(data))

    output = io.BytesIO()
    mutated.save(output, format="PNG")
    return output.getvalue()


def _crop_png(png_bytes, size):
    with Image.open(io.BytesIO(png_bytes)) as image:
        cropped = image.crop((0, 0, size[0], size[1]))
    output = io.BytesIO()
    cropped.save(output, format="PNG")
    return output.getvalue()


def _animated_png_bytes():
    frames = [
        Image.new("RGBA", (24, 24), (20, 40, 80, 255)),
        Image.new("RGBA", (24, 24), (80, 40, 20, 255)),
    ]
    output = io.BytesIO()
    frames[0].save(
        output,
        format="PNG",
        save_all=True,
        append_images=frames[1:],
        duration=100,
        loop=0,
    )
    return output.getvalue()


def test_png_adapter_registered_and_qr_stays_unsupported():
    assert carrier_registry.registered_kinds() == (PNG_LOSSLESS_V1,)
    assert isinstance(
        carrier_registry.get_adapter(PNG_LOSSLESS_V1),
        PngLosslessCarrierAdapter,
    )

    with pytest.raises(CarrierUnsupportedError) as exc_info:
        carrier_registry.get_adapter(QR_MATRIX_V1)

    _assert_generic_error(exc_info, QR_MATRIX_V1)


def test_png_capacity_estimate_is_deterministic_for_small_and_large_covers():
    small = _png_bytes(size=(32, 32))
    large = _png_bytes(size=(96, 64))

    small_estimate = carrier_registry.estimate_capacity(
        PNG_LOSSLESS_V1,
        small,
        payload_size=_expected_capacity(32, 32),
    )
    assert small_estimate.capacity_bytes == _expected_capacity(32, 32)
    assert small_estimate.fits is True

    large_estimate = carrier_registry.estimate_capacity(
        PNG_LOSSLESS_V1,
        large,
        payload_size=_expected_capacity(96, 64) + 1,
    )
    assert large_estimate.capacity_bytes == _expected_capacity(96, 64)
    assert large_estimate.fits is False


def test_png_round_trip_extracts_exact_original_payload_bytes():
    payload = b"PARC\x00message-bytes\xffpayload-secret-sentinel"
    cover = _png_bytes(size=(64, 64), mode="RGBA")

    output = carrier_registry.embed_envelope(
        PNG_LOSSLESS_V1,
        payload,
        carrier_bytes=cover,
    )

    assert output.mime_type == "image/png"
    assert output.filename == "carrier.png"
    assert output.carrier_bytes.startswith(PNG_SIGNATURE)
    assert output.carrier_bytes != cover
    assert carrier_registry.detect_carrier(output.carrier_bytes).kind == PNG_LOSSLESS_V1

    extracted = carrier_registry.extract_envelope(PNG_LOSSLESS_V1, output.carrier_bytes)
    assert extracted.envelope_bytes == payload


def test_png_insufficient_capacity_fails_before_output_save(monkeypatch):
    cover = _png_bytes(size=(16, 16))
    payload = b"A" * (_expected_capacity(16, 16) + 1)

    def fail_save(*_args, **_kwargs):
        pytest.fail("insufficient capacity reached output save")

    monkeypatch.setattr(Image.Image, "save", fail_save)

    with pytest.raises(CarrierLimitError) as exc_info:
        carrier_registry.embed_envelope(
            PNG_LOSSLESS_V1,
            payload,
            carrier_bytes=cover,
        )

    _assert_generic_error(exc_info, "capacity", "payload")


def test_png_oversized_carrier_input_rejected_before_adapter_work(monkeypatch):
    sentinel = "payload-secret-sentinel"
    monkeypatch.setattr(carrier_base, "MAX_CARRIER_FILE_BYTES", 8)

    with pytest.raises(CarrierLimitError) as exc_info:
        carrier_registry.detect_carrier(PNG_SIGNATURE + sentinel.encode("ascii"))

    _assert_generic_error(exc_info, sentinel)


@pytest.mark.parametrize(
    ("payload_kind", "limit_name"),
    [
        ("setup", "MAX_EXTRACTED_SETUP_BYTES"),
        ("message", "MAX_EXTRACTED_MESSAGE_BYTES"),
    ],
)
def test_png_extracted_payload_limits_apply_to_setup_and_message(
    monkeypatch,
    payload_kind,
    limit_name,
):
    payload = b"PARC-payload-secret-sentinel"
    output = carrier_registry.embed_envelope(
        PNG_LOSSLESS_V1,
        payload,
        carrier_bytes=_png_bytes(size=(64, 64)),
        payload_kind=payload_kind,
    )
    monkeypatch.setattr(carrier_base, limit_name, len(payload) - 1)

    with pytest.raises(CarrierLimitError) as exc_info:
        carrier_registry.extract_envelope(
            PNG_LOSSLESS_V1,
            output.carrier_bytes,
            payload_kind=payload_kind,
        )

    _assert_generic_error(exc_info, "payload-secret-sentinel")


def test_png_corrupt_png_rejected_generically():
    sentinel = "token-secret-sentinel"
    corrupt = PNG_SIGNATURE + b"not-a-real-png-" + sentinel.encode("ascii")

    with pytest.raises(CarrierAdapterError) as exc_info:
        carrier_registry.extract_envelope(PNG_LOSSLESS_V1, corrupt)

    _assert_generic_error(exc_info, sentinel)


def test_png_truncated_carrier_payload_rejected_generically():
    sentinel = "payload-secret-sentinel"
    output = carrier_registry.embed_envelope(
        PNG_LOSSLESS_V1,
        (sentinel * 16).encode("ascii"),
        carrier_bytes=_png_bytes(size=(80, 80)),
    )
    truncated = _crop_png(output.carrier_bytes, (20, 20))

    with pytest.raises(CarrierError) as exc_info:
        carrier_registry.extract_envelope(PNG_LOSSLESS_V1, truncated)

    _assert_generic_error(exc_info, sentinel, "length", "capacity")


@pytest.mark.parametrize(
    ("label", "bit_index"),
    [
        ("magic", 0),
        ("length", len(PNG_CONTAINER_MAGIC) * 8),
        ("checksum", PNG_CONTAINER_HEADER_BYTES * 8),
    ],
)
def test_png_tampered_container_fields_rejected_generically(label, bit_index):
    sentinel = "payload-secret-sentinel"
    output = carrier_registry.embed_envelope(
        PNG_LOSSLESS_V1,
        sentinel.encode("ascii"),
        carrier_bytes=_png_bytes(size=(64, 64)),
    )
    tampered = _flip_hidden_bit(output.carrier_bytes, bit_index)

    with pytest.raises(CarrierError) as exc_info:
        carrier_registry.extract_envelope(PNG_LOSSLESS_V1, tampered)

    _assert_generic_error(exc_info, sentinel, label, "checksum", "length")


def test_png_multiframe_carrier_rejected_generically():
    carrier = _animated_png_bytes()

    with pytest.raises(CarrierAdapterError) as exc_info:
        carrier_registry.estimate_capacity(PNG_LOSSLESS_V1, carrier, payload_size=1)

    _assert_generic_error(exc_info, "frame", "animated")


def test_png_over_budget_image_rejected_generically():
    sentinel = "path-secret-sentinel"
    carrier = _png_metadata_bytes(6000, 5000) + sentinel.encode("ascii")

    with pytest.raises(CarrierAdapterError) as exc_info:
        carrier_registry.estimate_capacity(PNG_LOSSLESS_V1, carrier, payload_size=1)

    _assert_generic_error(exc_info, sentinel, "pixel", "dimension")


def test_png_output_does_not_preserve_source_metadata():
    sentinel = "metadata-token-secret-sentinel"
    pnginfo = PngImagePlugin.PngInfo()
    pnginfo.add_text("Secret", sentinel)
    cover = _png_bytes(size=(64, 64), pnginfo=pnginfo)

    output = carrier_registry.embed_envelope(
        PNG_LOSSLESS_V1,
        b"PARC-message",
        carrier_bytes=cover,
    )

    assert sentinel.encode("ascii") not in output.carrier_bytes
    with Image.open(io.BytesIO(output.carrier_bytes)) as image:
        assert "Secret" not in image.info


def test_png_errors_do_not_echo_payload_path_token_or_raw_bytes(caplog):
    sentinels = (
        "payload-secret-sentinel",
        "path-secret-sentinel",
        "token-secret-sentinel",
    )
    caplog.clear()

    with pytest.raises(CarrierAdapterError) as exc_info:
        carrier_registry.embed_envelope(
            PNG_LOSSLESS_V1,
            b"payload-secret-sentinel",
            carrier_bytes=b"not-a-png path-secret-sentinel token-secret-sentinel",
        )

    _assert_generic_error(exc_info, *sentinels)
    for sentinel in sentinels:
        assert sentinel not in caplog.text
