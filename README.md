# SIBIONICS CGM for Home Assistant

[![HACS Custom](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://hacs.xyz/)
[![HA Version](https://img.shields.io/badge/HA-2025.1%2B-blue.svg)](https://www.home-assistant.io/)

Home Assistant integration for the **SIBIONICS GS1** Continuous Glucose Monitor. Connects directly to the sensor via Bluetooth LE — no phone app or cloud required.

Uses the **real SIBIONICS calibration algorithm** (ARM64 binary emulation) for medically accurate readings: 97% within ±2 mg/dL of the official app.

## Features

- **Direct BLE connection** — no SIBIONICS app, no cloud, no internet needed
- **Real-time glucose** — live readings every 60 seconds
- **Full calibration** — runs the actual algorithm binary via ARM64 emulation, not a simplified formula
- **Auto-discovery** — HA detects the sensor automatically via Bluetooth
- **Reconnection** — automatic reconnect on BLE disconnection
- **Persistent history** — readings survive HA restarts (last 24 hours stored locally)
- **Trend arrows** — rapid rise/rise/slow rise/stable/slow fall/fall/rapid fall

## Entities

| Entity | Type | Unit | Default | Description |
|--------|------|------|---------|-------------|
| **Glucose** | Sensor | mg/dL | Enabled | Calibrated glucose reading |
| Glucose (mmol/L) | Sensor | mmol/L | Disabled | Same reading in mmol/L |
| Glucose Trend | Sensor | — | Enabled | Trend arrow (stable, rising, falling, etc.) |
| Battery | Sensor | % | Enabled | Sensor battery level |
| Last Reading | Sensor | timestamp | Enabled | Time of last glucose reading |
| Connection | Binary Sensor | — | Enabled | BLE connection status |
| Sensor Temperature | Sensor | °C | Disabled | Subcutaneous temperature |
| Raw Glucose | Sensor | mmol/L | Disabled | Pre-calibration raw value |
| Reading Count | Sensor | — | Disabled | Total readings processed |
| Device State | Sensor | — | Disabled | Internal state (connecting, authenticated, receiving) |

## Requirements

- Home Assistant 2025.1 or newer
- Bluetooth adapter on the HA host (built-in or USB)
- SIBIONICS GS1 sensor (active, on body)
- QR code from the sensor packaging
- **Phone Bluetooth must be disconnected** from the sensor (only one BLE connection at a time)

## Installation

### HACS (recommended)

1. Open HACS in Home Assistant
2. Go to **Integrations** → three-dot menu → **Custom repositories**
3. Add `https://github.com/chalimov/sibionics_cgm_ha` as an **Integration**
4. Search for "SIBIONICS CGM" and install
5. Restart Home Assistant

### Manual

Copy the `custom_components/sibionics_cgm` folder to your Home Assistant `config/custom_components/` directory and restart.

## Setup

1. Make sure the **SIBIONICS phone app is disconnected** from the sensor (close the app or turn off phone Bluetooth)
2. In Home Assistant, go to **Settings → Devices & Services → Add Integration**
3. Search for **SIBIONICS CGM**
   - If HA already discovered the sensor via Bluetooth, it will appear automatically
   - Otherwise, select from the list of detected SIBIONICS devices
4. **Scan the QR code** on the sensor packaging and paste the full string
   - Example: `(01)06972831641063(11)250805(17)270204(10)LT48250770N(21)250770QF32450CAA59`
5. Confirm the setup — the calibration engine initializes on first connection

The QR code provides the per-sensor sensitivity parameter required for accurate calibration. Each sensor has a unique sensitivity value encoded in its serial number.

## How It Works

```
Sensor (BLE)          Integration                        Home Assistant
┌──────────┐    ┌──────────────────────┐    ┌─────────────────────────┐
│ GS1      │───>│ RC4 decrypt          │───>│ sensor.glucose          │
│ nRF52832 │    │ Parse glucose records │    │ sensor.glucose_mmol     │
│          │<───│ RC4 encrypt auth      │    │ sensor.glucose_trend    │
│ Service  │    │                      │    │ sensor.battery          │
│ 0xFF30   │    │ ARM64 Emulator       │    │ sensor.temperature      │
│          │    │ (Unicorn Engine)     │    │ binary_sensor.connection│
└──────────┘    │ libnative-algorithm  │    └─────────────────────────┘
                │ -v1_1_6A.so         │
                └──────────────────────┘
```

1. **BLE Discovery** — HA detects the sensor's service UUID (`0xFF30`)
2. **Authentication** — RC4-encrypted auth packet with session key credential
3. **History burst** — sensor sends all stored readings (every minute since activation)
4. **Calibration** — each reading passes through the real algorithm binary via ARM64 emulation
5. **Live updates** — new reading pushed every 60 seconds
6. **Trend calculation** — computed from last 15 minutes of calibrated readings

### Why ARM64 Emulation?

The SIBIONICS algorithm has a multi-stage pipeline: Kalman filter, temperature compensation, IIR biquad filters, deconvolution, adaptive calibration. A simplified formula gives ±3 mg/dL at steady state but ±30+ during rapid glucose changes (meal spikes). Running the real binary gives ±2 everywhere.

## Supported Variants

| Variant | Status | Auth | Algorithm |
|---------|--------|------|-----------|
| **EU** (`com.sisensing.sijoy`) | Supported | RC4 encrypted | v1_1_6A |
| Russia (`com.sisensing.rusibionics`) | Untested | RC4 encrypted | v1_1_6A |
| China (`com.sisensing.sisensingcgm`) | Not supported | Unencrypted | v1_1_5G |
| Sibionics 2 (`com.sisensing.eco`) | Not supported | RC4 encrypted | v1_1_5G |

## Troubleshooting

**"No SIBIONICS CGM sensors found"**
- Make sure the sensor is active (applied to body, not expired)
- Disconnect the SIBIONICS phone app — BLE only supports one connection
- Check that your HA host has a working Bluetooth adapter
- Try moving the HA host closer to the sensor

**"Emulator error" / calibration engine fails**
- The `unicorn` Python package must be installed (included in `requirements`)
- The `.so` library files must be present in `custom_components/sibionics_cgm/lib/`

**Readings differ from official app**
- The first few readings after connection may differ while the algorithm's internal filters converge
- After the history burst is processed, live readings should match within ±2 mg/dL

**Connection drops frequently**
- BLE range is limited (~5-10 meters) — keep HA host close to the sensor
- The integration auto-reconnects after 60 seconds

## References

- [SIBIONICS GS1 BLE Protocol & Calibration](https://github.com/chalimov/cgm) — the reverse-engineering research project this integration is built on. Contains the full BLE protocol documentation, encryption details, and standalone calibration scripts.
- [Juggluco](https://github.com/j-kaltes/Juggluco) — open-source CGM app (GPL v3) whose source code helped identify the correct algorithm library and parameters
- [SIBIONICS GS1 BLE Protocol Specification](https://github.com/chalimov/cgm/blob/main/SIBIONICS_GS1_BLE_Protocol.md) — complete byte-level protocol documentation
- [SIBIONICS API Protocol](https://github.com/chalimov/cgm/blob/main/SIBIONICS_API_PROTOCOL.md) — cloud REST API documentation

## License

Research project. The SIBIONICS algorithm libraries (`lib/*.so`) are extracted from the SIBIONICS APK and are subject to SIBIONICS' terms. The integration code is original work.
