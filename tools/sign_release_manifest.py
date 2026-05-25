"""Create an offline Ed25519 signature for a canonical release manifest."""

from __future__ import annotations

import argparse
import base64
import os
import stat
from getpass import getpass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def sign_manifest(
    key_path: Path,
    manifest_path: Path,
    output_path: Path,
    passphrase: bytes,
    *,
    overwrite: bool = False,
) -> bytes:
    """Sign exact manifest bytes with the encrypted offline Ed25519 key."""
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing signature: {output_path}")
    loaded_key = load_pem_private_key(key_path.read_bytes(), password=passphrase)
    if not isinstance(loaded_key, Ed25519PrivateKey):
        raise ValueError("The supplied private key is not an Ed25519 key.")

    signature = loaded_key.sign(manifest_path.read_bytes())
    output_path.write_bytes(signature)
    if os.name != "nt":
        output_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return signature


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign a Paracci SHA256SUMS.txt manifest offline.")
    parser.add_argument("manifest", type=Path, help="Path to the exact downloaded SHA256SUMS.txt file.")
    parser.add_argument(
        "--key",
        type=Path,
        default=Path("signing_key.pem"),
        help="Encrypted release-signing private key PEM (default: signing_key.pem).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("SHA256SUMS.txt.sig"),
        help="Detached raw-signature output path (default: SHA256SUMS.txt.sig).",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite an existing signature output file.")
    args = parser.parse_args()

    passphrase = getpass("Signing-key passphrase: ").encode("utf-8")
    signature = sign_manifest(args.key, args.manifest, args.output, passphrase, overwrite=args.force)
    print(f"Raw Ed25519 signature written to: {args.output.resolve()}")
    print("Provide this public Base64 signature to the publish_signed_release workflow:")
    print(base64.b64encode(signature).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
