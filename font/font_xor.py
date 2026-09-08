#!/usr/bin/env python3
"""Decrypt or encrypt STAR OCEAN: THE DIVINE FORCE font files.

Examples:
    python font_xor.py decrypt name.ttf
    python font_xor.py encrypt decrypt/name.ttf

Decrypted fonts and their ``.xor`` key files are written to ``decrypt/``.
Encrypted fonts are written to ``encrypt/``.  Only the folder belonging to the
selected action is created, and it is always next to this script.
"""
import argparse
import struct
from pathlib import Path


SCRIPT_ROOT = Path(__file__).resolve().parent
DECRYPT_DIR = SCRIPT_ROOT / "decrypt"
ENCRYPT_DIR = SCRIPT_ROOT / "encrypt"

FONT_EXTENSIONS = {".ttf", ".otf", ".ttc", ".otc"}
SFNT_SIGNATURES = (b"\x00\x01\x00\x00", b"OTTO")


def xor4(data: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[index % 4] for index, value in enumerate(data))


def valid_sfnt(data: bytes) -> bool:
    if len(data) < 12 or data[:4] not in SFNT_SIGNATURES:
        return False
    count = struct.unpack_from(">H", data, 4)[0]
    end = 12 + count * 16
    if not count or end > len(data):
        return False
    for pos in range(12, end, 16):
        offset, length = struct.unpack_from(">II", data, pos + 8)
        if offset > len(data) or length > len(data) - offset:
            return False
    return True


def infer_key(data: bytes):
    for signature in SFNT_SIGNATURES:
        key = bytes(a ^ b for a, b in zip(data[:4], signature))
        decoded = xor4(data, key)
        if valid_sfnt(decoded):
            return key, decoded
    return None, None


def read_key(path: Path) -> bytes:
    value = path.read_text(encoding="ascii").strip()
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{path}: invalid hex key") from exc
    if len(key) != 4:
        raise ValueError(f"{path}: key must be exactly 4 bytes")
    return key


def write_key(path: Path, key: bytes) -> None:
    path.write_text(key.hex() + "\n", encoding="ascii", newline="\n")


def decrypt_file(path: Path) -> str:
    data = path.read_bytes()
    if valid_sfnt(data):
        print(f"skip      {path}: already decrypted")
        return "skipped"
    key, decoded = infer_key(data)
    if key is None:
        print(f"skip      {path}: cannot infer XOR key")
        return "skipped"
    output_font = DECRYPT_DIR / path.name
    output_key = DECRYPT_DIR / (path.stem + ".xor")
    output_font.write_bytes(decoded)
    write_key(output_key, key)
    print(f"decrypted {path} -> {output_font} (key={key.hex()})")
    return "decrypted"


def encrypt_file(path: Path) -> str:
    data = path.read_bytes()
    if not valid_sfnt(data):
        print(f"skip      {path}: input is not a valid unencrypted SFNT")
        return "skipped"
    candidates = [
        path.with_suffix(".xor"),
        DECRYPT_DIR / (path.stem + ".xor"),
    ]
    key_file = next((p for p in candidates if p.exists()), None)
    if key_file is None:
        print(f"skip      {path}: missing {path.stem}.xor")
        return "skipped"
    key = read_key(key_file)
    encoded = xor4(data, key)
    output_font = ENCRYPT_DIR / path.name
    output_font.write_bytes(encoded)
    print(f"encrypted {path} -> {output_font} (key={key.hex()})")
    return "encrypted"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("decrypt", "encrypt"))
    parser.add_argument("paths", nargs="+", help="font file(s) to process")
    args = parser.parse_args(argv)

    if args.action == "decrypt":
        DECRYPT_DIR.mkdir(parents=True, exist_ok=True)
    else:
        ENCRYPT_DIR.mkdir(parents=True, exist_ok=True)

    counts = {}
    for raw_path in args.paths:
        path = Path(raw_path).resolve()
        if not path.is_file():
            print(f"skip      {path}: not a file")
            status = "skipped"
        elif path.suffix.lower() not in FONT_EXTENSIONS:
            print(f"skip      {path}: unsupported font extension")
            status = "skipped"
        else:
            status = decrypt_file(path) if args.action == "decrypt" else encrypt_file(path)
        counts[status] = counts.get(status, 0) + 1

    summary = ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
    print("\n" + (summary if summary else "no files processed"))


if __name__ == "__main__":
    main()
