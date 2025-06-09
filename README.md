# NetSec3 Secure Chat

This project provides a simple secure chat application demonstrating:

- Elliptic Curve Diffie-Hellman key exchange
- Challenge‑response user authentication
- AES‑GCM encrypted messaging

## Setup

Install the required packages:

```bash
pip install -r requirements.txt
```

Run the test suite to verify everything works:

```bash
pytest -q
```

## Usage

### Start the server

```bash
python -m netsec3.v3.chat_server <port>
```

Choose any free port between `1025` and `65535`.

### Run the client

```bash
python -m netsec3.v3.chat_client_secure <host> <port>
```

Use the same `<port>` used when starting the server and replace `<host>` with the server's IP address.
