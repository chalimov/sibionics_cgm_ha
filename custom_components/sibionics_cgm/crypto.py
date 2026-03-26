"""SIBIONICS GS1 BLE encryption, decryption, and packet construction.

All BLE packets are RC4-encrypted with the MASTER KEY.
The session key is a credential placed inside the auth packet, not the encryption key.
"""

from __future__ import annotations

import struct

from .const import MASTER_KEY, SESSION_KEYS


class RC4:
    """Standard RC4 stream cipher."""

    def __init__(self, key: bytes, drop: int = 0):
        self.S = list(range(256))
        j = 0
        key_len = len(key)
        for i in range(256):
            j = (j + self.S[i] + key[i % key_len]) & 0xFF
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0
        for _ in range(drop):
            self.i = (self.i + 1) & 0xFF
            self.j = (self.j + self.S[self.i]) & 0xFF
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]

    def xor(self, data: bytes) -> bytes:
        output = bytearray(len(data))
        for k in range(len(data)):
            self.i = (self.i + 1) & 0xFF
            self.j = (self.j + self.S[self.i]) & 0xFF
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            output[k] = data[k] ^ self.S[(self.S[self.i] + self.S[self.j]) & 0xFF]
        return bytes(output)


def rc4_encrypt(data: bytes, key: bytes = MASTER_KEY) -> bytes:
    """RC4 encrypt/decrypt (symmetric)."""
    return RC4(key).xor(data)


def _checksum(data: bytes) -> int:
    """Two's complement checksum: -(sum of bytes) & 0xFF."""
    return (-sum(data)) & 0xFF


def make_auth_packet(mac_reversed: bytes, variant: str = "eu") -> bytes:
    """Build 26-byte auth packet, RC4-encrypted with master key.

    Args:
        mac_reversed: 6-byte BLE MAC address in reversed order.
        variant: Sensor variant key (eu, russia, china, eco).
    """
    session_key = SESSION_KEYS.get(variant, SESSION_KEYS["eu"])
    pkt = bytearray(26)
    pkt[0] = 0x19  # Auth command LE of 0x0119
    pkt[1] = 0x01
    pkt[2] = 0x00  # Auth flag
    pkt[3:9] = mac_reversed
    pkt[9:25] = session_key
    pkt[25] = _checksum(pkt[:25])
    return rc4_encrypt(bytes(pkt))


def make_activation_packet(timestamp: int) -> bytes:
    """Build 11-byte activation packet."""
    pkt = bytearray(11)
    pkt[0], pkt[1] = 0x0A, 0x07
    struct.pack_into("<I", pkt, 2, timestamp & 0xFFFFFFFF)
    struct.pack_into("<I", pkt, 6, 1234)
    pkt[10] = _checksum(pkt[:10])
    return rc4_encrypt(bytes(pkt))


def make_time_sync_packet(timestamp: int) -> bytes:
    """Build 7-byte time sync packet."""
    pkt = bytearray(7)
    pkt[0], pkt[1] = 0x06, 0x03
    struct.pack_into("<I", pkt, 2, timestamp & 0xFFFFFFFF)
    pkt[6] = _checksum(pkt[:6])
    return rc4_encrypt(bytes(pkt))


def make_data_request_packet(index: int = 0) -> bytes:
    """Build 7-byte data request packet."""
    pkt = bytearray(7)
    pkt[0], pkt[1] = 0x06, 0x08
    struct.pack_into("<H", pkt, 2, index & 0xFFFF)
    pkt[6] = _checksum(pkt[:6])
    return rc4_encrypt(bytes(pkt))


def decrypt_response(data: bytes) -> bytes:
    """Decrypt an incoming BLE notification from the sensor."""
    return rc4_encrypt(data)  # RC4 is symmetric


def parse_mac_address(address: str) -> bytes:
    """Parse BLE address string to reversed 6-byte MAC."""
    sep = ":" if ":" in address else "-"
    parts = address.split(sep)
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC address format: {address} (expected 6 octets)")
    mac = bytes(int(x, 16) for x in parts)
    return bytes(reversed(mac))


def mmol_to_mgdl(mmol: float) -> int:
    """Convert mmol/L to mg/dL (rounded)."""
    return round(mmol * 18.0182)


def mgdl_to_mmol(mgdl: float) -> float:
    """Convert mg/dL to mmol/L."""
    return round(mgdl / 18.0182, 1)
