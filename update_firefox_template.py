#!/usr/bin/env python3
"""
Update crates/tunnel/src/templates.rs from a captured Firefox ClientHello.

Usage examples:
  python3 update_firefox_template.py --hex "160301..."
  python3 update_firefox_template.py --input firefox_client_hello.txt
  python3 update_firefox_template.py --input firefox_client_hello.txt --check-only

The input may contain whitespace, newlines, colons, commas, or 0x prefixes.
The script validates that the payload is a single TLS ClientHello record that
kanotls can still patch in-place, then rewrites the Rust byte array constant.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
TEMPLATE_FILE = REPO_ROOT / "crates" / "tunnel" / "src" / "templates.rs"
CONST_NAME = "FIREFOX_BOOTSTRAP_CLIENT_HELLO"
LINE_WIDTH = 16
X25519_GROUP = 0x001D
PADDING_EXTENSION = 0x0015


class ValidationError(Exception):
    pass


@dataclass
class ClientHelloSummary:
    total_len: int
    tls_record_len: int
    handshake_len: int
    session_id_len: int
    cipher_suites_len: int
    compression_methods_len: int
    extensions_len: int
    sni: str
    x25519_share_len: int
    alpn_protocols: list[str]
    warnings: list[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate and update Firefox ClientHello template")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--hex", help="Hex string captured from a Firefox ClientHello")
    source.add_argument("--input", help="Path to a text file containing the captured hex string")
    parser.add_argument(
        "--output",
        default=str(TEMPLATE_FILE),
        help="Rust template file to rewrite (default: crates/tunnel/src/templates.rs)",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Validate input and print a summary without rewriting any files",
    )
    return parser.parse_args()


def load_raw_input(args: argparse.Namespace) -> str:
    if args.hex is not None:
        return args.hex
    return Path(args.input).read_text(encoding="utf-8")


def normalize_hex(raw: str) -> str:
    cleaned = raw.replace("0x", "").replace("0X", "")
    cleaned = re.sub(r"[\s,:;\[\]\(\){}]+", "", cleaned)
    if not cleaned:
        raise ValidationError("input is empty after removing separators")
    if re.search(r"[^0-9a-fA-F]", cleaned):
        raise ValidationError("input contains non-hex characters")
    if len(cleaned) % 2 != 0:
        raise ValidationError("hex string length must be even")
    return cleaned.lower()


def u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise ValidationError(f"truncated u16 at offset {offset}")
    return int.from_bytes(data[offset : offset + 2], "big")


def u24(data: bytes, offset: int) -> int:
    if offset + 3 > len(data):
        raise ValidationError(f"truncated u24 at offset {offset}")
    return int.from_bytes(data[offset : offset + 3], "big")


def decode_ascii(data: bytes, what: str) -> str:
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{what} is not valid ASCII") from exc


def validate_client_hello(data: bytes) -> ClientHelloSummary:
    warnings: list[str] = []

    if len(data) < 9:
        raise ValidationError("record is too short to contain a TLS ClientHello")
    if data[0] != 0x16:
        raise ValidationError(f"first record type must be 0x16 (Handshake), got 0x{data[0]:02x}")

    tls_record_len = u16(data, 3)
    if tls_record_len != len(data) - 5:
        raise ValidationError(
            f"TLS record length mismatch: header says {tls_record_len}, actual payload is {len(data) - 5}"
        )

    if data[5] != 0x01:
        raise ValidationError(f"handshake type must be ClientHello (0x01), got 0x{data[5]:02x}")

    handshake_len = u24(data, 6)
    if handshake_len != len(data) - 9:
        raise ValidationError(
            f"handshake length mismatch: header says {handshake_len}, actual body is {len(data) - 9}"
        )

    if data[9:11] != b"\x03\x03":
        warnings.append(
            f"legacy ClientHello version is 0x{data[9]:02x}{data[10]:02x}, expected 0x0303 for modern TLS 1.3"
        )

    session_id_len = data[43]
    session_id_start = 44
    session_id_end = session_id_start + session_id_len
    if session_id_end > len(data):
        raise ValidationError("truncated session_id")
    if session_id_len < 32:
        raise ValidationError(f"session_id must be at least 32 bytes for kanotls, got {session_id_len}")

    cursor = session_id_end
    cipher_suites_len = u16(data, cursor)
    cursor += 2
    if cipher_suites_len == 0 or cipher_suites_len % 2 != 0:
        raise ValidationError(f"cipher_suites length must be a non-zero even number, got {cipher_suites_len}")
    cipher_suites_end = cursor + cipher_suites_len
    if cipher_suites_end > len(data):
        raise ValidationError("truncated cipher_suites")
    cursor = cipher_suites_end

    if cursor >= len(data):
        raise ValidationError("missing compression methods length")
    compression_methods_len = data[cursor]
    cursor += 1
    compression_methods_end = cursor + compression_methods_len
    if compression_methods_end > len(data):
        raise ValidationError("truncated compression methods")
    cursor = compression_methods_end

    extensions_len = u16(data, cursor)
    cursor += 2
    extensions_end = cursor + extensions_len
    if extensions_end != len(data):
        raise ValidationError(
            f"extensions block mismatch: expected to end at {extensions_end}, total length is {len(data)}"
        )

    sni: str | None = None
    x25519_share_len: int | None = None
    alpn_protocols: list[str] = []
    has_supported_versions = False
    has_signature_algorithms = False

    while cursor + 4 <= extensions_end:
        ext_type = u16(data, cursor)
        ext_len = u16(data, cursor + 2)
        ext_data = cursor + 4
        ext_end = ext_data + ext_len
        if ext_end > extensions_end:
            raise ValidationError(f"truncated extension 0x{ext_type:04x}")

        if ext_type == 0x0000:
            if ext_len < 5:
                raise ValidationError("server_name extension is too short")
            list_len = u16(data, ext_data)
            if ext_data + 2 + list_len != ext_end:
                raise ValidationError("server_name list length mismatch")
            if data[ext_data + 2] != 0x00:
                raise ValidationError("server_name entry is not a host_name")
            name_len = u16(data, ext_data + 3)
            name_start = ext_data + 5
            name_end = name_start + name_len
            if name_end > ext_end:
                raise ValidationError("truncated SNI hostname")
            sni = decode_ascii(data[name_start:name_end], "SNI hostname")

        elif ext_type == 0x0010:
            if ext_len < 2:
                raise ValidationError("ALPN extension is too short")
            alpn_len = u16(data, ext_data)
            if ext_data + 2 + alpn_len != ext_end:
                raise ValidationError("ALPN length mismatch")
            alpn_cursor = ext_data + 2
            while alpn_cursor < ext_end:
                proto_len = data[alpn_cursor]
                alpn_cursor += 1
                proto_end = alpn_cursor + proto_len
                if proto_end > ext_end:
                    raise ValidationError("truncated ALPN protocol entry")
                alpn_protocols.append(decode_ascii(data[alpn_cursor:proto_end], "ALPN protocol"))
                alpn_cursor = proto_end

        elif ext_type == 0x002B:
            has_supported_versions = True

        elif ext_type == 0x000D:
            has_signature_algorithms = True

        elif ext_type == 0x0033:
            if ext_len < 4:
                raise ValidationError("key_share extension is too short")
            share_list_len = u16(data, ext_data)
            if ext_data + 2 + share_list_len != ext_end:
                raise ValidationError("key_share list length mismatch")
            share_cursor = ext_data + 2
            while share_cursor + 4 <= ext_end:
                group = u16(data, share_cursor)
                share_len = u16(data, share_cursor + 2)
                share_start = share_cursor + 4
                share_end = share_start + share_len
                if share_end > ext_end:
                    raise ValidationError("truncated key_share entry")
                if group == X25519_GROUP:
                    x25519_share_len = share_len
                share_cursor = share_end

        elif ext_type == PADDING_EXTENSION:
            if any(byte != 0 for byte in data[ext_data:ext_end]):
                raise ValidationError(
                    "padding extension_data must be all zero per RFC 7685"
                )

        cursor = ext_end

    if cursor != extensions_end:
        raise ValidationError("extension parsing did not end on the expected boundary")
    if sni is None:
        raise ValidationError("missing SNI extension")
    if x25519_share_len is None:
        raise ValidationError("missing X25519 key_share entry")
    if x25519_share_len != 32:
        raise ValidationError(f"X25519 key_share length must be 32 bytes, got {x25519_share_len}")

    if not has_supported_versions:
        warnings.append("supported_versions extension is missing")
    if not has_signature_algorithms:
        warnings.append("signature_algorithms extension is missing")
    if "h2" not in alpn_protocols:
        warnings.append("ALPN does not include h2")
    if "http/1.1" not in alpn_protocols:
        warnings.append("ALPN does not include http/1.1")

    return ClientHelloSummary(
        total_len=len(data),
        tls_record_len=tls_record_len,
        handshake_len=handshake_len,
        session_id_len=session_id_len,
        cipher_suites_len=cipher_suites_len,
        compression_methods_len=compression_methods_len,
        extensions_len=extensions_len,
        sni=sni,
        x25519_share_len=x25519_share_len,
        alpn_protocols=alpn_protocols,
        warnings=warnings,
    )


def format_rust_array(data: bytes) -> str:
    lines: list[str] = []
    for start in range(0, len(data), LINE_WIDTH):
        chunk = data[start : start + LINE_WIDTH]
        rendered = ", ".join(f"0x{byte:02x}" for byte in chunk)
        lines.append(f"    {rendered},")
    return "\n".join(lines)


def render_template_file(data: bytes) -> str:
    return (
        f"pub(crate) const {CONST_NAME}: &[u8] = &[\n"
        f"{format_rust_array(data)}\n"
        "];\n"
    )


def print_summary(summary: ClientHelloSummary) -> None:
    print("Validation passed")
    print(f"total bytes: {summary.total_len}")
    print(f"tls record payload length: {summary.tls_record_len}")
    print(f"handshake body length: {summary.handshake_len}")
    print(f"session_id length: {summary.session_id_len}")
    print(f"cipher_suites length: {summary.cipher_suites_len}")
    print(f"compression methods length: {summary.compression_methods_len}")
    print(f"extensions length: {summary.extensions_len}")
    print(f"sni: {summary.sni}")
    print(f"x25519 share length: {summary.x25519_share_len}")
    print(f"alpn: {', '.join(summary.alpn_protocols) if summary.alpn_protocols else '(none)'}")
    if summary.warnings:
        print("warnings:")
        for warning in summary.warnings:
            print(f"  - {warning}")


def main() -> int:
    args = parse_args()
    try:
        normalized = normalize_hex(load_raw_input(args))
        data = bytes.fromhex(normalized)
        summary = validate_client_hello(data)
    except (OSError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print_summary(summary)

    if args.check_only:
        return 0

    output_path = Path(args.output)
    output_path.write_text(render_template_file(data), encoding="utf-8")
    print(f"updated: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
