# GitHub IP Sync to Hetzner Robot Firewall

This script automatically updates the firewall rules of your Hetzner **Robot (dedicated server)** to allow incoming traffic from GitHub's webhook IP addresses.

It pulls the latest GitHub IPs from their public API and merges them into your existing firewall rules, without touching other rules like SSH or custom entries.

## Features

- Automatically fetches GitHub webhook IP ranges
- Preserves existing firewall rules
- Only updates if IPs have changed
- Designed to run in a container or as a background process

## Requirements

- Python 3.7+
- Hetzner Robot credentials
- Access to the Hetzner Robot Firewall API

## Installation

1. Clone the repo or copy the script files.
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file:
```env
HETZNER_USERNAME=your-robot-username
HETZNER_PASSWORD=your-robot-password
SERVER_IDS=123456,654321
```

## Usage

To run the script once:
```bash
python main.py
```

To run it continuously (e.g. in Docker or a background process), the script includes a loop that checks every hour by default.

## Notes

- Only IPv4 addresses are added due to Hetzner Robot's current limitations.
- The script only touches rules prefixed with `github_`.
- Output rules are preserved exactly as-is.

## License

MIT