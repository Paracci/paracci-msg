"""Generate the offline Ed25519 private key used to sign release manifests."""

from __future__ import annotations

import argparse
import os
import stat
from getpass import getpass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    PublicFormat,
)


def generate_signing_key(output_path: Path, passphrase: bytes) -> bytes:
    """Write an encrypted private PEM once and return its raw public key."""
    if output_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing private key: {output_path}")
    if not passphrase:
        raise ValueError("The private-key passphrase must not be empty.")

    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        BestAvailableEncryption(passphrase),
    )
    output_path.write_bytes(pem)
    if os.name != "nt":
        output_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Paracci's offline release-signing key.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("signing_key.pem"),
        help="Encrypted private-key PEM output path (default: signing_key.pem).",
    )
    args = parser.parse_args()

    first = getpass("New signing-key passphrase: ").encode("utf-8")
    second = getpass("Confirm signing-key passphrase: ").encode("utf-8")
    if first != second:
        raise SystemExit("Passphrases did not match; no key was written.")

    public_key = generate_signing_key(args.output, first)
    print(f"Encrypted private key written to: {args.output.resolve()}")
    print("Keep this PEM offline and do not add it to GitHub Actions secrets.")
    print("Paste the following constant into paracci/desktop/updater.py:")
    print("UPDATE_SIGNING_PUBLIC_KEY = bytes.fromhex(")
    print(f'    "{public_key.hex()}"')
    print(")")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
