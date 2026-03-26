"""Constants for the SIBIONICS CGM integration."""

DOMAIN = "sibionics_cgm"
MANUFACTURER = "SIBIONICS"
MODEL = "GS1"

# ── BLE Service & Characteristics ─────────────────────────────────────
SERVICE_UUID = "0000ff30-0000-1000-8000-00805f9b34fb"
NOTIFY_CHAR_UUID = "0000ff31-0000-1000-8000-00805f9b34fb"  # Sensor -> Client
WRITE_CHAR_UUID = "0000ff32-0000-1000-8000-00805f9b34fb"   # Client -> Sensor

# Standard GATT characteristics for device info
CHAR_MODEL = "00002a24-0000-1000-8000-00805f9b34fb"
CHAR_SERIAL = "00002a25-0000-1000-8000-00805f9b34fb"
CHAR_FIRMWARE = "00002a26-0000-1000-8000-00805f9b34fb"
CHAR_BATTERY = "00002a19-0000-1000-8000-00805f9b34fb"

# ── RC4 Encryption ────────────────────────────────────────────────────
MASTER_KEY = bytes.fromhex("01380b9a005b025dcd9ec3990937aae8")

# Session keys are credentials embedded in the auth packet, NOT encryption keys
SESSION_KEYS = {
    "eu": b"THE544U0TYITE461",
    "russia": b"LQSS54U0RURUA99J",
    "china": b"GKSHGDU0TYA456G4",
    "eco": b"GKSHGDU0TYA456G4",
}

# EU auth trigger (magic bytes received on first notification)
EU_AUTH_TRIGGER = bytes([0x23, 0xF7, 0x6F, 0xD9, 0xF4])

# ── Algorithm Parameters ──────────────────────────────────────────────
BG_REFERENCE = 0.0
TARGET_LOW = 4.4    # mmol/L (EU variant)
TARGET_HIGH = 11.1  # mmol/L (EU variant)

# Algorithm context size (jni_algorithm_context_t)
CTX_SIZE = 0x6D8

# ── Config Flow ───────────────────────────────────────────────────────
CONF_QR_CODE = "qr_code"
CONF_SENSOR_SERIAL = "sensor_serial"
CONF_SENSITIVITY_INPUT = "sensitivity_input"
CONF_BLE_MATCH_KEY = "ble_match_key"
CONF_VARIANT = "variant"

# ── Timing ────────────────────────────────────────────────────────────
SCAN_TIMEOUT = 30
RECONNECT_INTERVAL = 60      # seconds between reconnect attempts
LIVE_UPDATE_INTERVAL = 60    # sensor sends live reading every 60s
DATA_STALE_TIMEOUT = 600     # mark data stale after 10 minutes of silence

# ── Trend Arrows ──────────────────────────────────────────────────────
TREND_ARROWS = {
    -3: "rapid_fall",
    -2: "falling",
    -1: "slow_fall",
    0: "stable",
    1: "slow_rise",
    2: "rising",
    3: "rapid_rise",
}

TREND_ICONS = {
    "rapid_fall": "mdi:arrow-down-bold",
    "falling": "mdi:arrow-down",
    "slow_fall": "mdi:arrow-bottom-right",
    "stable": "mdi:arrow-right",
    "slow_rise": "mdi:arrow-top-right",
    "rising": "mdi:arrow-up",
    "rapid_rise": "mdi:arrow-up-bold",
}
