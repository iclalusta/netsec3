"""Helper utilities for the chat server."""

from __future__ import annotations

import base64
import logging
import os
import time
import re
from collections import defaultdict
from typing import Tuple, Any, Dict

try:
    from . import crypto_utils
    from . import config
except ImportError:  # pragma: no cover - fallback when run as script
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    import crypto_utils  # type: ignore
    import config  # type: ignore

# Precompiled username pattern
USERNAME_RE = re.compile(config.USERNAME_PATTERN)

# Track requests per IP for simple rate limiting
request_tracker: dict[str, list[float]] = defaultdict(list)

# Cache of used internal nonces
used_internal_nonces: dict[str, float] = {}


def validate_username_format(username: str) -> bool:
    """Return True if the username matches the allowed format."""
    return isinstance(username, str) and bool(USERNAME_RE.fullmatch(username))


def validate_password_format(password: str) -> bool:
    """Return True if the password meets length requirements."""
    return isinstance(password, str) and 6 <= len(password) <= 128


def validate_message_content(content: str) -> bool:
    """Return True if message content length is within allowed bounds."""
    return isinstance(content, str) and 1 <= len(content) <= config.MAX_MSG_LENGTH


def validate_broadcast_content(content: str) -> bool:
    """Return True if broadcast content length is within allowed bounds."""
    return isinstance(content, str) and 1 <= len(content) <= config.MAX_MSG_LENGTH


def validate_username_password_format(username: str, password: str) -> Tuple[bool, str]:
    """Validate username and password and return (is_valid, message)."""
    if not validate_username_format(username):
        return False, "Invalid username format."
    if not validate_password_format(password):
        return False, "Password must be 6-128 characters."
    return True, ""


def is_rate_limited(ip_address: str) -> bool:
    """Return True if the IP address has exceeded the request rate limit."""
    now = time.time()
    timestamps = request_tracker[ip_address]
    timestamps.append(now)
    # Remove entries outside the window
    request_tracker[ip_address] = [t for t in timestamps if now - t < config.REQUEST_WINDOW_SECONDS]
    return len(request_tracker[ip_address]) > config.MAX_REQUESTS_PER_WINDOW


def validate_internal_nonce(nonce_value: str) -> bool:
    """Return True if the internal nonce is unused and not expired."""
    now = time.time()
    ts = used_internal_nonces.get(nonce_value)
    if ts and now - ts < config.INTERNAL_NONCE_EXPIRY_SECONDS:
        return False
    used_internal_nonces[nonce_value] = now
    return True


def validate_timestamp_internal(timestamp_str: str) -> bool:
    """Return True if a timestamp string is within the allowed window."""
    try:
        ts = float(timestamp_str)
    except ValueError:
        return False
    return abs(time.time() - ts) <= config.TIMESTAMP_WINDOW_SECONDS


def send_encrypted_response(sock: Any, client_address: Tuple[str, int], channel_sk: bytes, response_payload_dict: Dict[str, Any]) -> None:
    """Utility to encrypt and send a JSON payload back to the client."""
    resp_bytes = crypto_utils.serialize_payload(response_payload_dict)
    enc_blob = crypto_utils.encrypt_aes_gcm(channel_sk, resp_bytes)
    sock.sendto(enc_blob.encode("utf-8"), client_address)


def relay_raw(sock: Any, header: str, sender_addr: Tuple[str, int], raw_blob: str) -> None:
    """Relay an encrypted blob between two clients."""
    target, _, rest = raw_blob.partition(":")
    if not rest:
        logging.warning("Malformed %s from %s", header, sender_addr)
        return
    target_addr = None
    for addr, sess in client_sessions.items():
        if sess.get("username") == target and sess.get("channel_sk"):
            target_addr = addr
            break
    if not target_addr:
        logging.info("%s target %s not found", header, target)
        return
    sock.sendto(f"{header}:{raw_blob}".encode("utf-8"), target_addr)
    sender_user = client_sessions.get(sender_addr, {}).get("username", sender_addr)
    logging.info("Relayed %s from %s to %s (len=%d)", header, sender_user, target, len(raw_blob))


# ---------------------------------------------------------------------------
# Session tracking / notifications
# ---------------------------------------------------------------------------

# Client session tracking shared with server module
client_sessions: Dict[Tuple[str, int], Dict[str, Any]] = {}
active_usernames: Dict[str, Tuple[str, int]] = {}


def notify_user_logout(sock: Any, username: str) -> None:
    """Notify all connected clients that ``username`` signed out."""
    for addr, sess in list(client_sessions.items()):
        if (
            sess.get("username")
            and sess.get("username") != username
            and sess.get("channel_sk")
        ):
            send_encrypted_response(
                sock,
                addr,
                sess["channel_sk"],
                {"type": "USER_LOGOUT", "user": username},
            )

