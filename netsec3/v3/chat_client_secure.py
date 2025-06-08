"""Secure chat client with modular command handling.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.validation import Validator
from prompt_toolkit.patch_stdout import patch_stdout
from rich.console import Console
from rich.theme import Theme
from rich.progress import Progress

try:
    from . import crypto_utils
except ImportError:
    sys.path.insert(0, os.path.dirname(__file__))
    import crypto_utils

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

USERNAME_PATTERN = r"^[A-Za-z][A-Za-z0-9_]{2,15}$"
KEY_EXCHANGE_TIMEOUT = int(os.getenv("KEY_EXCHANGE_TIMEOUT", 10))
RECEIVE_TIMEOUT = float(os.getenv("RECEIVE_TIMEOUT", 1.0))
AUTH_TIMEOUT = int(os.getenv("AUTH_TIMEOUT", 5))
LOG_FILE = os.getenv("CLIENT_LOG_FILE", "client.log")
CUSTOM_PROMPT = os.getenv("CHAT_PROMPT", "] ")
NS_NONCE_SIZE = crypto_utils.AES_GCM_NONCE_SIZE
HANDSHAKE_TIMEOUT = int(os.getenv("HANDSHAKE_TIMEOUT", 10))
SESSION_KEY_LIFETIME = int(os.getenv("SESSION_KEY_LIFETIME", 3600))


@dataclass
class ClientConfig:
    """Runtime configuration for the client."""

    key_exchange_timeout: int = KEY_EXCHANGE_TIMEOUT
    receive_timeout: float = RECEIVE_TIMEOUT
    auth_timeout: int = AUTH_TIMEOUT
    username_pattern: str = USERNAME_PATTERN
    log_file: str = LOG_FILE
    prompt: str = CUSTOM_PROMPT


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

stop_event = threading.Event()
is_authenticated = False
client_username: str | None = None

client_ecdh_private_key = None
channel_sk: bytes | None = None
key_exchange_complete = threading.Event()

auth_challenge_data = None
auth_successful_event = threading.Event()

server_addr_global: tuple[str, int] | None = None
session_keys: dict[str, dict] = {}
handshake_events: dict[str, threading.Event] = {}

# These will be initialized in setup()
console: Console
session: PromptSession
command_completer: WordCompleter
config = ClientConfig()


# ---------------------------------------------------------------------------
# Setup functions
# ---------------------------------------------------------------------------

def setup_environment(cfg: ClientConfig) -> None:
    """Configure logging, console and prompt session."""

    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s - CLIENT - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(cfg.log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )

    theme = Theme({
        "system": "cyan",
        "server": "green",
        "error": "bold red",
        "client": "yellow",
    })
    global console, session, command_completer
    console = Console(theme=theme, markup=False, highlight=False)
    session = PromptSession()
    command_completer = WordCompleter(
        [
            "signup",
            "signin",
            "message",
            "broadcast",
            "greet",
            "help",
            "logs",
            "exit",
        ],
        ignore_case=True,
    )


def print_command_list() -> None:
    """Display available commands."""

    commands = (
        "signup      Sign up with a new username and password\n"
        "signin      Log in with your credentials\n"
        "message     Send a private message: message <target> <content>\n"
        "broadcast   Send a message to all users: broadcast <content>\n"
        "greet       Send a friendly greeting\n"
        "logs        Show chat history\n"
        "exit        Quit the application"
    )
    console.print(commands, style="system", markup=False)
    console.print("Type `help` at any time for details.", style="system")
    console.print()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def prompt_text(message: str, *, validator: Validator | None = None,
                is_password: bool = False) -> str:
    """Prompt the user for input and clear the validator afterwards."""

    text = session.prompt(message, validator=validator,
                          is_password=is_password).strip()
    session.default_buffer.validator = None
    return text


def generate_nonce() -> str:
    """Return a unique nonce string."""

    nonce = str(uuid.uuid4())
    logging.debug("Generated nonce %s", nonce)
    return nonce


def generate_nonce_bytes() -> bytes:
    """Return cryptographically random nonce bytes."""
    nonce = os.urandom(NS_NONCE_SIZE)
    logging.debug("Generated nonce bytes %s", base64.b64encode(nonce)[:8])
    return nonce


def get_non_empty_validator() -> Validator:
    """Return a validator that ensures input is not empty."""

    return Validator.from_callable(
        lambda text: len(text.strip()) > 0,
        error_message="Input required",
        move_cursor_to_end=True,
    )


def get_username_validator() -> Validator:
    """Return a validator for user names."""

    pattern = re.compile(config.username_pattern)
    return Validator.from_callable(
        lambda text: bool(pattern.fullmatch(text.strip())),
        error_message=(
            "Username must start with a letter and contain only letters, "
            "numbers or '_' (3-16 chars)"
        ),
        move_cursor_to_end=True,
    )


# ---------------------------------------------------------------------------
# Network / crypto helpers
# ---------------------------------------------------------------------------

def perform_key_exchange(sock: socket.socket,
                         server_address: tuple[str, int]) -> bool:
    """Execute ECDH key exchange with the server."""

    global client_ecdh_private_key
    try:
        client_ecdh_private_key, pub_key = crypto_utils.generate_ecdh_keys()
        pub_key_b64 = crypto_utils.serialize_ecdh_public_key(pub_key)
        sock.sendto(f"DH_INIT:{pub_key_b64}".encode("utf-8"), server_address)
        console.print(
            "<System> Attempting to establish secure channel with server...",
            style="system",
        )
        with Progress(transient=True) as progress:
            task = progress.add_task(
                "[system]Performing key exchange...",
                total=config.key_exchange_timeout,
            )
            start = time.time()
            while not key_exchange_complete.is_set():
                if time.time() - start >= config.key_exchange_timeout:
                    break
                progress.advance(task)
                time.sleep(1)

        if not key_exchange_complete.is_set():
            console.print(
                "! Secure channel setup failed: no response from server.",
                style="error",
            )
            logging.warning("Key exchange timeout waiting for server response")
            return False

        if channel_sk:
            console.print(
                "<System> Secure channel established with server via ECDH.",
                style="system",
            )
            logging.info("ECDH key exchange successful")
            return True

        console.print(
            "! Secure channel setup failed: Could not derive shared key.",
            style="error",
        )
        logging.error("Key exchange event set but channel key missing")
        return False

    except Exception as exc:
        logging.error("Error during ECDH key exchange: %s", exc, exc_info=True)
        console.print(f"! Secure channel setup failed: {exc}", style="error")
        return False


def send_secure_command(sock: socket.socket, server_address: tuple[str, int],
                        command_header: str, payload: dict) -> None:
    """Encrypt and send a command payload to the server."""

    if not channel_sk:
        console.print("! Cannot send command: Secure channel not established.",
                      style="error")
        return
    try:
        plaintext = crypto_utils.serialize_payload(payload)
        encrypted = crypto_utils.encrypt_aes_gcm(channel_sk, plaintext)
        final_msg = f"{command_header.upper()}:{encrypted}"
        logging.debug(
            "Sending %s to server (blob length %d)",
            command_header.upper(),
            len(encrypted),
        )
        sock.sendto(final_msg.encode("utf-8"), server_address)
    except Exception as exc:
        console.print(
            f"\n! Error sending secure command '{command_header}': {exc}",
            style="error",
        )
        logging.error(
            "Error sending secure command '%s': %s",
            command_header,
            exc,
            exc_info=True,
        )


def send_secure_text(sock: socket.socket, server_address: tuple[str, int],
                     command_header: str, text: str) -> None:
    """Encrypt plaintext under ChannelSK and send with a header."""
    if not channel_sk:
        console.print("! Cannot send command: Secure channel not established.",
                      style="error")
        return
    try:
        encrypted = crypto_utils.encrypt_aes_gcm(channel_sk, text.encode("utf-8"))
        final_msg = f"{command_header}:{encrypted}"
        sock.sendto(final_msg.encode("utf-8"), server_address)
        logging.debug("Sent %s to server", command_header)
    except Exception as exc:  # pragma: no cover - network failures
        logging.error("Error sending %s: %s", command_header, exc, exc_info=True)


def send_relay_message(sock: socket.socket, server_address: tuple[str, int],
                       command_header: str, *parts: str) -> None:
    """Send a plaintext message via the server relay to another peer."""
    msg = f"{command_header}:{':'.join(parts)}"
    sock.sendto(msg.encode("utf-8"), server_address)
    logging.debug("Relayed %s message", command_header)


def request_session_key(sock: socket.socket, server_address: tuple[str, int],
                        peer: str) -> None:
    """Initiate Needham-Schroeder session key request with the server."""
    nonce1 = base64.b64encode(generate_nonce_bytes()).decode()
    handshake_events[peer] = threading.Event()
    session_keys[peer] = {"nonce1": nonce1, "state": "req"}
    send_secure_text(sock, server_address, "NS_REQ", f"{peer}:{nonce1}")
    logging.info("Requested session key for %s", peer)


def send_ns_ticket(sock: socket.socket, server_address: tuple[str, int],
                   peer: str) -> None:
    entry = session_keys.get(peer)
    if not entry:
        return
    key = entry["key"]
    nonce2 = generate_nonce_bytes()
    entry["nonce2"] = nonce2
    handshake_events.setdefault(peer, threading.Event()).clear()
    enc_nonce2 = crypto_utils.encrypt_aes_gcm_with_nonce(key, nonce2, nonce2)
    send_relay_message(
        sock,
        server_address,
        "NS_TICKET",
        peer,
        client_username or "",
        entry["ticket"],
        enc_nonce2,
    )
    entry["state"] = "ticket_sent"
    logging.info("Sent NS_TICKET to %s", peer)


def handle_ns_resp(sock: socket.socket, server_address: tuple[str, int], peer: str,
                   encrypted_blob: str) -> None:
    """Process server NS_RESP and send ticket to peer."""
    try:
        decrypted = crypto_utils.decrypt_aes_gcm(channel_sk, encrypted_blob)
        data = crypto_utils.deserialize_payload(decrypted)
    except Exception as exc:
        logging.error("Failed to decrypt NS_RESP: %s", exc, exc_info=True)
        return
    entry = session_keys.get(peer)
    if not entry or data.get("nonce1") != entry.get("nonce1"):
        logging.warning("Invalid or unexpected NS_RESP for %s", peer)
        return
    key_bytes = base64.b64decode(data.get("K_AB", ""))
    entry.update(
        {
            "key": key_bytes,
            "ticket": data.get("ticket"),
            "timestamp": time.time(),
            "state": "got_key",
        }
    )
    handshake_events.setdefault(peer, threading.Event()).clear()
    send_ns_ticket(sock, server_address, peer)


def handle_ns_ticket(
    sock: socket.socket,
    server_address: tuple[str, int],
    sender: str,
    ticket: str,
    encrypted_nonce2: str,
) -> None:
    """Handle incoming NS_TICKET from another client."""
    try:
        ticket_plain = crypto_utils.decrypt_aes_gcm(channel_sk, ticket)
        tdata = crypto_utils.deserialize_payload(ticket_plain)
        key_bytes = base64.b64decode(tdata.get("K_AB", ""))
        peer = tdata.get("sender", sender)
    except Exception as exc:
        logging.error("Failed to process ticket from %s: %s", sender, exc,
                      exc_info=True)
        return
    entry = session_keys.setdefault(peer, {})
    entry.update({"key": key_bytes, "ticket": ticket, "timestamp": time.time()})
    handshake_events.setdefault(peer, threading.Event()).clear()
    nonce2 = crypto_utils.decrypt_aes_gcm(key_bytes, encrypted_nonce2)
    nonce3 = generate_nonce_bytes()
    entry.update({"nonce2": nonce2, "nonce3": nonce3})
    n2_minus = (int.from_bytes(nonce2, "big") - 1) % (1 << (8 * NS_NONCE_SIZE))
    plaintext = n2_minus.to_bytes(NS_NONCE_SIZE, "big") + nonce3
    enc_auth = crypto_utils.encrypt_aes_gcm_with_nonce(key_bytes, nonce3, plaintext)
    send_relay_message(sock, server_address, "NS_AUTH", peer, client_username or "", enc_auth)
    entry["state"] = "auth_sent"


def complete_ns_auth(sock: socket.socket, server_address: tuple[str, int], peer: str,
                      encrypted_auth: str) -> None:
    """Finish handshake after receiving NS_AUTH from peer."""
    entry = session_keys.get(peer)
    if not entry:
        return
    key = entry["key"]
    nonce2 = entry.get("nonce2")
    if not nonce2:
        return
    data = crypto_utils.decrypt_aes_gcm(key, encrypted_auth)
    n2_minus1 = data[:NS_NONCE_SIZE]
    nonce3 = data[NS_NONCE_SIZE:]
    expected = ((int.from_bytes(nonce2, "big") - 1) % (1 << (8 * NS_NONCE_SIZE)))
    if n2_minus1 != expected.to_bytes(NS_NONCE_SIZE, "big"):
        logging.warning("Nonce verification failed for peer %s", peer)
        return
    entry["nonce3"] = nonce3
    n3_minus = (int.from_bytes(nonce3, "big") - 1) % (1 << (8 * NS_NONCE_SIZE))
    enc_fin = crypto_utils.encrypt_aes_gcm_with_nonce(
        key, nonce3, n3_minus.to_bytes(NS_NONCE_SIZE, "big")
    )
    send_relay_message(
        sock, server_address, "NS_FIN", peer, client_username or "", enc_fin
    )
    entry["state"] = "complete"
    entry["timestamp"] = time.time()
    if peer in handshake_events:
        handshake_events[peer].set()


def handle_ns_fin(sender: str, encrypted_fin: str) -> None:
    """Verify final handshake message from peer."""
    entry = session_keys.get(sender)
    if not entry:
        return
    key = entry.get("key")
    nonce3 = entry.get("nonce3")
    if not (key and nonce3):
        return
    data = crypto_utils.decrypt_aes_gcm(key, encrypted_fin)
    expected = (
        (int.from_bytes(nonce3, "big") - 1) % (1 << (8 * NS_NONCE_SIZE))
    )
    if data == expected.to_bytes(NS_NONCE_SIZE, "big"):
        entry["state"] = "complete"
        entry["timestamp"] = time.time()
        handshake_events.setdefault(sender, threading.Event()).set()


# ---------------------------------------------------------------------------
# Message receiver
# ---------------------------------------------------------------------------

def handle_encrypted_payload(payload: dict) -> None:
    """Process a decrypted payload from the server."""

    global is_authenticated, client_username, auth_challenge_data

    msg_type = payload.get("type")
    msg_status = payload.get("status")
    msg_detail = payload.get("detail", "")

    if msg_type == "AUTH_RESPONSE":
        if msg_status == "SIGNUP_OK":
            console.print(
                "<Server> Signup successful! You can now signin.",
                style="server",
            )
        elif msg_status == "SIGNUP_FAIL":
            console.print(
                f"<Server> Signup failed: {msg_detail}",
                style="error",
            )
        else:
            console.print(
                f"<Server> Unexpected signup response: {msg_status}: "
                f"{msg_detail}",
                style="error",
            )

    elif msg_type == "AUTH_CHALLENGE":
        auth_challenge_data = {
            "challenge": payload.get("challenge"),
            "salt": payload.get("salt"),
            "iterations": payload.get(
                "pbkdf2_iterations", crypto_utils.PBKDF2_ITERATIONS
            ),
            "key_length": payload.get(
                "pbkdf2_key_length", crypto_utils.PBKDF2_KEY_LENGTH
            ),
        }
        if not (
            auth_challenge_data["challenge"]
            and auth_challenge_data["salt"]
        ):
            console.print(
                "\n<Server> Received incomplete auth challenge.",
                style="error",
            )
            auth_challenge_data = None
        else:
            logging.debug(
                "Auth challenge received: %s...",
                auth_challenge_data["challenge"][:10],
            )


    elif msg_type == "AUTH_RESULT":
        if payload.get("success"):
            is_authenticated = True
            console.print(
                f"<Server> Welcome, {client_username}!",
                style="server",
            )
        else:
            is_authenticated = False
            client_username = None
            console.print(
                f"<Server> Signin failed: {msg_detail}",
                style="error",
            )
        auth_successful_event.set()

    elif msg_type == "GREETING_RESPONSE":
        if payload.get("status") == "GREETING_OK":
            console.print(
                f"<Server> Greeting acknowledged! {msg_detail}",
                style="server",
            )
        else:
            console.print(
                f"<Server> Greeting response: "
                f"{payload.get('status')} - {msg_detail}",
                style="server",
            )

    elif msg_type == "SECURE_MESSAGE_INCOMING":
        console.print(
            f"<Secure Msg from {payload.get('from_user', 'Unknown')} "
            f"({payload.get('timestamp', '?')})> {payload.get('content', '')}",
            style="server",
        )

    elif msg_type == "BROADCAST_INCOMING":
        console.print(
            f"<Secure Bcast from {payload.get('from_user', 'Unknown')} "
            f"({payload.get('timestamp', '?')})> {payload.get('content', '')}",
            style="server",
        )

    elif msg_type == "MESSAGE_STATUS":
        console.print(
            f"<Server> {payload.get('status')}: {msg_detail}",
            style="server",
        )

    elif msg_type == "SERVER_ERROR":
        console.print(f"<Server> Error: {msg_detail}", style="error")

    else:
        logging.warning("Unknown message type from server: %s", msg_type)
        console.print(
            f"<Server> Unknown type {msg_type}: {msg_detail}",
            style="error",
        )


def receive_messages(sock: socket.socket) -> None:
    """Continuously receive and process messages from the server."""

    global channel_sk

    while not stop_event.is_set():
        try:
            sock.settimeout(config.receive_timeout)
            data, _ = sock.recvfrom(4096)
            message_str = data.decode("utf-8")
            logging.debug("Raw received from server: '%s'", message_str[:100])

            if message_str.startswith("DH_RESPONSE:"):
                if client_ecdh_private_key:
                    try:
                        server_pub_key_b64 = message_str.split(":", 1)[1]
                        server_pub_key = (
                            crypto_utils.deserialize_ecdh_public_key(
                                server_pub_key_b64
                            )
                        )
                        channel_sk = crypto_utils.derive_shared_key_ecdh(
                            client_ecdh_private_key,
                            server_pub_key,
                        )
                        key_exchange_complete.set()
                        logging.debug(
                            "Derived ChannelSK via ECDH: %s...",
                            channel_sk.hex()[:16],
                        )
                    except Exception as exc:
                        logging.error(
                            "Failed to process KEY_EXCHANGE_RESPONSE: %s",
                            exc,
                            exc_info=True,
                        )
                        console.print(
                            f"! Error processing server's key: {exc}",
                            style="error",
                        )
                        key_exchange_complete.set()
                else:
                    logging.warning(
                        "Received KEY_EXCHANGE_RESPONSE but client ECDH "
                        "state not ready."
                    )
                continue

            if not channel_sk:
                logging.warning(
                    "Received non-key-exchange message but no ChannelSK: %s",
                    message_str,
                )
                continue

            parts = message_str.split(":", 4)
            header = parts[0]
            if header == "NS_RESP" and len(parts) >= 3:
                handle_ns_resp(sock, server_addr_global, parts[1], parts[2])
                continue
            if header == "NS_TICKET" and len(parts) >= 5:
                handle_ns_ticket(sock, server_addr_global, parts[2], parts[3], parts[4])
                continue
            if header == "NS_AUTH" and len(parts) >= 4:
                complete_ns_auth(sock, server_addr_global, parts[2], parts[3])
                continue
            if header == "NS_FIN" and len(parts) >= 4:
                handle_ns_fin(parts[2], parts[3])
                continue
            if header == "CHAT" and len(parts) >= 5:
                sender = parts[2]
                nonce = base64.b64decode(parts[3])
                ciphertext = parts[4]
                entry = session_keys.get(sender)
                if entry and entry.get("key"):
                    try:
                        pt = crypto_utils.decrypt_aes_gcm_detached(entry["key"], nonce, ciphertext)
                        with patch_stdout(raw=True):
                            console.print(f"<{sender}> {pt.decode()}", style="server")
                    except Exception as exc:
                        logging.warning("Failed to decrypt CHAT from %s: %s", sender, exc)
                continue
            if header == "BCAST" and len(parts) >= 5:
                sender = parts[2]
                nonce = base64.b64decode(parts[3])
                ciphertext = parts[4]
                entry = session_keys.get(sender)
                if entry and entry.get("key"):
                    try:
                        pt = crypto_utils.decrypt_aes_gcm_detached(entry["key"], nonce, ciphertext)
                        with patch_stdout(raw=True):
                            console.print(f"<Bcast {sender}> {pt.decode()}", style="server")
                    except Exception as exc:
                        logging.warning("Failed to decrypt BCAST from %s: %s", sender, exc)
                continue

            try:
                decrypted = crypto_utils.decrypt_aes_gcm(
                    channel_sk,
                    message_str,
                )
                payload = crypto_utils.deserialize_payload(decrypted)
                logging.debug(
                    "Decrypted payload from server: %s",
                    payload,
                )
                handle_encrypted_payload(payload)
            except ValueError as exc:
                logging.error(
                    "Failed to decrypt/decode server message: %s", exc
                )
                console.print(
                    "\n<System> Error processing message from server.",
                    style="error",
                )
            except Exception as exc:
                logging.error(
                    "Unexpected error processing server message: %s",
                    exc,
                    exc_info=True,
                )
                console.print(
                    f"\n<System> Unexpected error processing message: {exc}",
                    style="error",
                )

        except socket.timeout:
            continue
        except socket.error as exc:
            if not stop_event.is_set():
                logging.error("Socket error in receive_messages: %s", exc)
            break
        except Exception as exc:
            if not stop_event.is_set():
                logging.error(
                    "Unexpected error in receive_messages: %s", exc,
                    exc_info=True,
                )
            break

    logging.info("Receive thread stopped.")


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def handle_signup(
    sock: socket.socket, server_address: tuple[str, int]
) -> None:
    """Process the signup command."""

    uname = prompt_text(
        "Enter username for signup: ", validator=get_username_validator()
    )
    pword = prompt_text(
        "Enter password for signup: ",
        validator=get_non_empty_validator(),
        is_password=True,
    )
    if not uname or not pword:
        console.print(
            "<System> Username/password cannot be empty.",
            style="error",
        )
        return

    payload = {"username": uname, "password": pword, "nonce": generate_nonce()}
    send_secure_command(sock, server_address, "SECURE_SIGNUP", payload)
    console.print(f"\n<System> Signing up as {uname}...", style="system")


def handle_signin(
    sock: socket.socket, server_address: tuple[str, int]
) -> None:
    """Process the signin command using challenge-response."""

    global client_username, auth_challenge_data

    uname = prompt_text(
        "Enter username for signin: ", validator=get_username_validator()
    )
    pword = prompt_text(
        "Enter password for signin: ",
        validator=get_non_empty_validator(),
        is_password=True,
    )
    if not uname or not pword:
        console.print(
            "<System> Username/password cannot be empty.",
            style="error",
        )
        return

    client_username = uname
    auth_challenge_data = None
    auth_successful_event.clear()
    send_secure_command(
        sock,
        server_address,
        "AUTH_REQUEST",
        {"username": uname},
    )
    console.print(f"\n<System> Signing in as {uname}...", style="system")

    wait_start = time.time()
    while (
        auth_challenge_data is None
        and time.time() - wait_start < config.auth_timeout
        and not stop_event.is_set()
    ):
        time.sleep(0.1)

    if auth_challenge_data:
        try:
            salt_bytes = bytes.fromhex(auth_challenge_data["salt"])
            derived_key = crypto_utils.derive_password_verifier(
                pword,
                salt_bytes,
            )
            proof_bytes = crypto_utils.compute_hmac_sha256(
                derived_key, auth_challenge_data["challenge"]
            )
            proof_b64 = base64.b64encode(proof_bytes).decode("utf-8")
            send_secure_command(
                sock,
                server_address,
                "AUTH_RESPONSE",
                {
                    "challenge_response": proof_b64,
                    "client_nonce": generate_nonce(),
                },
            )
            wait_start = time.time()
            while (
                not auth_successful_event.is_set()
                and time.time() - wait_start < config.auth_timeout
                and not stop_event.is_set()
            ):
                time.sleep(0.1)
            if not auth_successful_event.is_set():
                console.print(
                    "<Server> Signin failed: no response from server",
                    style="error",
                )
                client_username = None
        except Exception as exc:
            console.print(f"<System> Error: {exc}", style="error")
            logging.error(
                "Client-side challenge processing error: %s",
                exc,
                exc_info=True,
            )
            client_username = None
    else:
        console.print(
            "<Server> Signin failed: challenge timeout",
            style="error",
        )
        client_username = None


def handle_message(sock: socket.socket, server_address: tuple[str, int],
                   action_input: str) -> None:
    """Send a private message to another user."""

    if not is_authenticated:
        console.print(
            "<System> Error: not signed in. Type `help` for usage.",
            style="error",
        )
        return

    parts = action_input.split(" ", 2)
    if len(parts) > 2 and parts[2].strip():
        target_user, msg_content = parts[1], parts[2]
        entry = session_keys.get(target_user)
        if not entry or entry.get("state") != "complete" or (
            time.time() - entry.get("timestamp", 0) > SESSION_KEY_LIFETIME
        ):
            request_session_key(sock, server_address, target_user)
            ev = handshake_events.get(target_user)
            if ev:
                ev.wait(timeout=HANDSHAKE_TIMEOUT)
        entry = session_keys.get(target_user)
        if not entry or entry.get("state") != "complete":
            console.print(f"<System> Handshake with {target_user} failed.", style="error")
            return
        key = entry["key"]
        nonce = generate_nonce_bytes()
        ct = crypto_utils.encrypt_aes_gcm_detached(key, nonce, msg_content.encode())
        send_relay_message(
            sock,
            server_address,
            "CHAT",
            target_user,
            client_username or "",
            base64.b64encode(nonce).decode(),
            ct,
        )
        console.print(f"<You> to {target_user}: {msg_content}", style="client")
    else:
        console.print(
            "<System> Error: usage message <target> <content>. "
            "Type `help` for usage.",
            style="error",
        )


def handle_broadcast(sock: socket.socket, server_address: tuple[str, int],
                     action_input: str) -> None:
    """Send a broadcast message to all users."""

    if not is_authenticated:
        console.print(
            "<System> Error: not signed in. Type `help` for usage.",
            style="error",
        )
        return

    parts = action_input.split(" ", 1)
    if len(parts) > 1 and parts[1].strip():
        msg_content = parts[1]
        for peer, entry in list(session_keys.items()):
            if (
                entry.get("state") != "complete"
                or time.time() - entry.get("timestamp", 0) > SESSION_KEY_LIFETIME
            ):
                request_session_key(sock, server_address, peer)
                evt = handshake_events.get(peer)
                if evt:
                    evt.wait(timeout=HANDSHAKE_TIMEOUT)
            entry = session_keys.get(peer)
            if not entry or entry.get("state") != "complete":
                continue
            nonce = generate_nonce_bytes()
            ct = crypto_utils.encrypt_aes_gcm_detached(
                entry["key"], nonce, msg_content.encode()
            )
            send_relay_message(
                sock,
                server_address,
                "BCAST",
                peer,
                client_username or "",
                base64.b64encode(nonce).decode(),
                ct,
            )
        console.print(f"<You> broadcast: {msg_content}", style="client")
    else:
        console.print(
            "<System> Error: usage broadcast <content>. "
            "Type `help` for usage.",
            style="error",
        )


def handle_greet(sock: socket.socket, server_address: tuple[str, int]) -> None:
    """Send a greeting to the server."""

    if not is_authenticated:
        console.print(
            "<System> Error: not signed in. Type `help` for usage.",
            style="error",
        )
    else:
        send_secure_command(
            sock, server_address, "GREET", {"nonce": generate_nonce()}
        )
        console.print("<You> greeting sent", style="client")


def handle_help() -> None:
    """Display help information."""

    print_command_list()


def handle_logs() -> None:
    """Display the log file if it exists."""

    try:
        with open(config.log_file, "r") as logf:
            console.pager(logf.read())
    except FileNotFoundError:
        console.print("<System> No log file found.", style="error")


def handle_exit() -> None:
    """Exit the application."""

    console.print("Exiting...", style="system")
    stop_event.set()


# ---------------------------------------------------------------------------
# Main command loop
# ---------------------------------------------------------------------------

def command_loop(sock: socket.socket, server_address: tuple[str, int]) -> None:
    """Prompt for commands until the user exits."""

    print_command_list()
    # Use patch_stdout with raw=True so ANSI color codes are preserved
    # when printing server messages during interactive prompts.
    with patch_stdout(raw=True):
        while not stop_event.is_set():
            try:
                action_input = session.prompt(
                    config.prompt,
                    completer=command_completer,
                    is_password=False,
                    validator=None,
                ).strip()
                if not action_input:
                    continue
                action_parts = action_input.split(" ", 1)
                action_cmd = action_parts[0].lower()

                if action_cmd == "signup":
                    handle_signup(sock, server_address)
                elif action_cmd == "signin":
                    handle_signin(sock, server_address)
                elif action_cmd == "message":
                    handle_message(sock, server_address, action_input)
                elif action_cmd == "broadcast":
                    handle_broadcast(sock, server_address, action_input)
                elif action_cmd == "greet":
                    handle_greet(sock, server_address)
                elif action_cmd == "help":
                    handle_help()
                elif action_cmd == "logs":
                    handle_logs()
                elif action_cmd == "exit":
                    handle_exit()
                else:
                    console.print(
                        f"<System> Error: unknown command '{action_input}'. "
                        "Type `help` for usage.",
                        style="error",
                    )

            except EOFError:
                stop_event.set()
            except KeyboardInterrupt:
                stop_event.set()
            except Exception as exc:
                logging.error(
                    "Error in client main loop: %s", exc, exc_info=True
                )
                console.print(
                    f"<System> An unexpected error occurred: {exc}",
                    style="error",
                )

    logging.info("Client main loop stopped.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_client(server_ip: str, server_port: int, cfg: ClientConfig) -> None:
    """Run the client against the specified server."""

    setup_environment(cfg)
    server_addr = (server_ip, server_port)
    global server_addr_global
    server_addr_global = server_addr
    client_sock: socket.socket | None = None
    receiver_thread: threading.Thread | None = None

    try:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        logging.info("Client socket created for %s", server_addr)
        receiver_thread = threading.Thread(
            target=receive_messages, args=(client_sock,), daemon=True
        )
        receiver_thread.start()

        if not perform_key_exchange(client_sock, server_addr):
            stop_event.set()
        else:
            command_loop(client_sock, server_addr)

    except socket.error as se:
        logging.critical("Client socket error: %s", se, exc_info=True)
        console.print(
            f"<System> Network error: {se}. Could not connect or communicate.",
            style="error",
        )
    except Exception as exc:
        logging.critical("Client critical setup error: %s", exc, exc_info=True)
        console.print(
            f"<System> A critical error occurred during client startup: {exc}",
            style="error",
        )
    finally:
        logging.info("Client shutting down...")
        console.print("<System> Shutting down client...", style="system")
        stop_event.set()
        if client_sock:
            client_sock.close()
        if receiver_thread and receiver_thread.is_alive():
            receiver_thread.join(timeout=1.0)
        logging.info("Client shutdown complete.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python chat_client_secure.py <server_ip> <server_port>")
        sys.exit(1)

    try:
        port = int(sys.argv[2])
        if not 1024 < port < 65536:
            raise ValueError("Port must be 1025-65535")
    except ValueError as exc:
        print(f"Invalid port: {exc}")
        sys.exit(1)

    run_client(sys.argv[1], port, config)
