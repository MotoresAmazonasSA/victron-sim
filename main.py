"""Victron BMS BLE advertisement simulator.

Builds the same manufacturer-data bytes that the ESP32 firmware in
Victron_Battery_-_Monitor/src/main.cpp scans for: a 10-byte header followed by
an AES-128-CTR encrypted, bit-packed BMS record.
"""

import os
import random
import struct
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi import FastAPI

VICTRON_VENDOR_ID = 0x02E1
BEACON_TYPE = 0x10          # Victron "instant readout" prefix
MODEL_ID = 0xA389           # arbitrary model id (firmware ignores it)
READOUT_TYPE = 0xA0
BMS_RECORD_TYPE = 0x0A

# Must match victronKey in main.cpp
VICTRON_KEY = bytes([
    0x07, 0x3A, 0x44, 0x3F, 0x80, 0xB5, 0xA3, 0x34,
    0xCB, 0xB8, 0x2E, 0xA4, 0x04, 0x29, 0x7E, 0x3B,
])

app = FastAPI(title="Victron BMS simulator")

# Simulated state, drifts a bit on every request
state = {"voltage": 13.2, "current": -5.0, "soc": 80.0, "consumed_ah": 20.0, "temperature": 25.0}


def put_bits_lsb(buf: bytearray, bit_pos: int, bit_len: int, value: int) -> None:
    """Inverse of getBitsLsb() in main.cpp."""
    value &= (1 << bit_len) - 1
    for i in range(bit_len):
        pos = bit_pos + i
        if (value >> i) & 1:
            buf[pos // 8] |= 1 << (pos % 8)


def encode_bms_data(voltage, current, soc, consumed_ah, temperature, ttg_minutes,
                    error=0, io_status=0, warnings_alarms=0) -> bytes:
    """Inverse of decodeBmsData() in main.cpp. Produces a 16-byte plaintext record."""
    data = bytearray(16)
    put_bits_lsb(data, 0, 8, error)
    put_bits_lsb(data, 8, 16, round(ttg_minutes))
    put_bits_lsb(data, 24, 16, round(voltage / 0.01))       # int16, 0.01 V
    put_bits_lsb(data, 40, 16, round(current / 0.1))        # int16, 0.1 A
    put_bits_lsb(data, 56, 16, io_status)
    put_bits_lsb(data, 72, 18, warnings_alarms)
    put_bits_lsb(data, 90, 10, round(soc / 0.1))            # 0.1 %
    put_bits_lsb(data, 100, 20, round(abs(consumed_ah) / 0.1))  # firmware negates it
    put_bits_lsb(data, 120, 7, round(temperature) + 40)     # offset -40 C
    return bytes(data)


def encrypt(nonce: int, plaintext: bytes) -> bytes:
    """AES-128-CTR, counter block = nonce (LE, 2 bytes) + 14 zero bytes, like decryptVictronData()."""
    counter = struct.pack("<H", nonce) + bytes(14)
    enc = Cipher(algorithms.AES(VICTRON_KEY), modes.CTR(counter)).encryptor()
    return enc.update(plaintext) + enc.finalize()


def build_manufacturer_data(plaintext: bytes, nonce: int) -> bytes:
    """Layout of VictronManufacturerData (packed, little-endian)."""
    header = struct.pack(
        "<HBHBBHB",
        VICTRON_VENDOR_ID,
        BEACON_TYPE,
        MODEL_ID,
        READOUT_TYPE,
        BMS_RECORD_TYPE,
        nonce,
        VICTRON_KEY[0],  # keyCheck
    )
    return header + encrypt(nonce, plaintext)


def step_state() -> None:
    state["current"] = max(-100.0, min(100.0, state["current"] + random.uniform(-2, 2)))
    state["soc"] = max(0.0, min(100.0, state["soc"] + state["current"] * 0.01))
    state["voltage"] = round(11.8 + 1.6 * state["soc"] / 100 + state["current"] * 0.005, 2)
    state["consumed_ah"] = max(0.0, state["consumed_ah"] - state["current"] * 0.01)
    state["temperature"] = max(-40.0, min(86.0, state["temperature"] + random.uniform(-0.3, 0.3)))


@app.get("/get_victron_data")
def get_victron_data(
    voltage: Optional[float] = None,
    current: Optional[float] = None,
    soc: Optional[float] = None,
    consumed_ah: Optional[float] = None,
    temperature: Optional[float] = None,
):
    """Return one simulated BLE advertisement. Any query param overrides the simulated value."""
    step_state()
    for key, val in (("voltage", voltage), ("current", current), ("soc", soc),
                     ("consumed_ah", consumed_ah), ("temperature", temperature)):
        if val is not None:
            state[key] = val

    ttg = 0xFFFF if state["current"] >= 0 else min(0xFFFE, round(
        (100 - state["consumed_ah"]) / -state["current"] * 60))

    plaintext = encode_bms_data(
        state["voltage"], state["current"], state["soc"],
        state["consumed_ah"], state["temperature"], ttg,
    )
    nonce = int.from_bytes(os.urandom(2), "little")
    payload = build_manufacturer_data(plaintext, nonce)

    return {
        "manufacturer_data": payload.hex(),   # raw bytes as advertised over BLE
        "length": len(payload),
        "values": {**{k: round(v, 2) for k, v in state.items()}, "ttg_minutes": ttg},
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
