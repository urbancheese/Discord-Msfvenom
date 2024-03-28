# Malicious Python Script

## Overview
- Designed for malicious purposes, including various functionalities.
- Intended for educational purposes only.

## Features
- Payload Generation: Generates payloads using `msfvenom`.
- Packing Payloads: Packs payloads into executables using `pyinstaller`.
- Word Document Manipulation: Creates Word documents with embedded macros.
- Discord Interaction: Sends payload download links and passwords over Discord.
- Process Manipulation: Hides process/window, adds to exclusions, and startup.
- UAC Bypass: Attempts to bypass User Account Control (UAC).
- Security Checks: Detects sandbox environments and debugging.
- Password Extraction: Extracts passwords from Edge and Chrome.

## Usage
1. Ensure Python is installed.
2. Install dependencies: `pip install -r requirements.txt`.
3. Customize `config.json`.
4. Run: `python malicious_script.py`.

## Configuration
- `config.json` parameters:
  - `LHOST`, `LPORT`, `PAYLOAD_PATH`, `WORD_DOC_PATH`.
  - `SERVER_CHANNEL_ID`, `BOT_TOKEN`, `CHANNEL_ID`.

## Disclaimer
- For educational purposes only.
- Authors not responsible for misuse or damage.
