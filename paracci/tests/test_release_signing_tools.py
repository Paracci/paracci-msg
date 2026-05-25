import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_tool(name: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "tools" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_offline_key_generation_and_manifest_signing_use_encrypted_pem(tmp_path):
    generator = load_tool("gen_signing_key")
    signer = load_tool("sign_release_manifest")
    key_path = tmp_path / "signing_key.pem"
    manifest_path = tmp_path / "SHA256SUMS.txt"
    signature_path = tmp_path / "SHA256SUMS.txt.sig"
    passphrase = b"offline-release-key-passphrase"
    manifest = b"4ba84b4189f029f4548da5d82737ab775cef5ef9b09be3667e4022ac63ff61cc  Paracci.exe\r\n"

    public_key = generator.generate_signing_key(key_path, passphrase)
    manifest_path.write_bytes(manifest)
    signature = signer.sign_manifest(key_path, manifest_path, signature_path, passphrase)

    assert b"ENCRYPTED PRIVATE KEY" in key_path.read_bytes()
    assert len(public_key) == 32
    assert signature_path.read_bytes() == signature
    assert len(signature) == 64
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, manifest)


def test_offline_key_generation_does_not_overwrite_private_key(tmp_path):
    generator = load_tool("gen_signing_key")
    key_path = tmp_path / "signing_key.pem"
    generator.generate_signing_key(key_path, b"first-passphrase")

    with pytest.raises(FileExistsError):
        generator.generate_signing_key(key_path, b"second-passphrase")
