# chat_client_secure.py
import socket
import sys
import threading
import time
import uuid
import logging
import base64
import os

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.validation import Validator, ValidationError
import re
from rich.console import Console
from rich.theme import Theme
from rich.progress import Progress

# Rich console for colorful output
theme = Theme({
    "system": "cyan",
    "server": "green",
    "error": "bold red",
    "client": "yellow",
})
console = Console(theme=theme)

try:
    import crypto_utils
except ImportError:
    console.print(
        "Error: crypto_utils.py not found. Make sure it's in the same directory.",
        style="error",
    )
    sys.exit(1)

# Configure logging. Set level to WARNING by default.
# Use DEBUG for troubleshooting. To see DEBUG logs, temporarily set
# level=logging.DEBUG.
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - CLIENT - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("client.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

# Prompt session with optional custom prompt
custom_prompt = os.environ.get("CHAT_PROMPT", "] ")
session = PromptSession()


def prompt_username(message: str) -> str:
    """Prompt user for a username with format validation."""
    uname = session.prompt(
        message,
        validator=username_validator,
        is_password=False,
    ).strip()
    # Clear validator so it does not persist for subsequent prompts
    session.default_buffer.validator = None
    return uname

command_completer = WordCompleter(
    ["signup", "signin", "message", "broadcast", "greet", "help", "logs", "exit"],
    ignore_case=True,
)

USERNAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,15}$")


def is_non_empty(text: str) -> bool:
    """Return True if the given text contains non-whitespace characters."""
    return len(text.strip()) > 0


def is_valid_username(text: str) -> bool:
    """Check that the text matches the allowed username format."""
    return bool(USERNAME_PATTERN.fullmatch(text.strip()))


non_empty_validator = Validator.from_callable(
    is_non_empty,
    error_message="Input required",
    move_cursor_to_end=True,
)

username_validator = Validator.from_callable(
    is_valid_username,
    error_message="Username must start with a letter and contain only letters, numbers or '_' (3-16 chars)",
    move_cursor_to_end=True,
)

stop_event = threading.Event()
is_authenticated = False
client_username = None

client_ecdh_private_key = None
channel_sk = None
key_exchange_complete = threading.Event()

auth_challenge_data = None
auth_successful_event = threading.Event()


def print_command_list():
    console.print(
        "signup      Sign up with a new username and password\n"
        "signin      Log in with your credentials\n"
        "message     Send a private message: message <target> <content>\n"
        f"broadcast   Send a message to all users: broadcast <content>\n"
        "greet       Send a friendly greeting\n"
        "logs        Show chat history\n"
        "exit        Quit the application",
        style="system",
        markup=False,
    )
    console.print("Type `help` at any time for details.", style="system")


def generate_nonce():
    nonce = str(uuid.uuid4())
    logging.debug(f"Client generated nonce: {nonce}")
    return nonce


def perform_key_exchange(sock, server_address):
    """Perform ECDH key exchange with the server."""
    global client_ecdh_private_key
    logging.debug("Initiating ECDH Key Exchange...")
    try:
        client_ecdh_private_key, client_public_key_obj = (
            crypto_utils.generate_ecdh_keys()
        )
        client_ecdh_public_key_b64 = crypto_utils.serialize_ecdh_public_key(
            client_public_key_obj
        )
        key_exchange_init_message = f"DH_INIT:{client_ecdh_public_key_b64}"
        sock.sendto(key_exchange_init_message.encode('utf-8'), server_address)
        short_pubkey = client_ecdh_public_key_b64[:30]
        logging.debug(
            "Sent KEY_EXCHANGE_INIT (DH_INIT protocol msg) to server with "
            f"ECDH pubkey: {short_pubkey}..."
        )
        console.print(
            "<System> Attempting to establish secure channel with server...",
            style="system",
            markup=False,
        )
        with Progress(transient=True) as progress:
            task = progress.add_task("[system]Performing key exchange...", total=10)
            start = time.time()
            while not key_exchange_complete.is_set() and time.time() - start < 10:
                progress.advance(task)
                time.sleep(1)

        if not key_exchange_complete.is_set():
            logging.warning(
                "KEY_EXCHANGE_RESPONSE timeout. "
                "Server did not respond or message lost."
            )
            console.print(
                "! Secure channel setup failed: no response from server.",
                style="error",
                markup=False,
            )
            return False

        if channel_sk:
            logging.info(
                "ECDH Key Exchange Successful. ChannelSK established."
            )  # Keep as INFO for this critical step
            console.print(
                "<System> Secure channel established with server via ECDH.",
                style="system",
                markup=False,
            )
            return True
        else:
            logging.error("Key exchange completed event set, but ChannelSK not derived.")
            console.print(
                "! Secure channel setup failed: Could not derive shared key.",
                style="error",
                markup=False,
            )
            return False
    except Exception as e:
        logging.error(f"Error during ECDH Key Exchange: {e}", exc_info=True)
        console.print(f"! Secure channel setup failed: {e}", style="error")
        return False


def receive_messages(sock):
    global is_authenticated, client_username, channel_sk, auth_challenge_data
    while not stop_event.is_set():
        try:
            sock.settimeout(1.0)
            data, server_addr = sock.recvfrom(4096)
            message_str = data.decode('utf-8')
            logging.debug(f"Raw received from server: '{message_str[:100]}...'")

            if message_str.startswith("DH_RESPONSE:"):
                if client_ecdh_private_key:
                    try:
                        server_pub_key_b64 = message_str.split(':', 1)[1]
                        server_public_key_obj = crypto_utils.deserialize_ecdh_public_key(server_pub_key_b64)
                        channel_sk = crypto_utils.derive_shared_key_ecdh(client_ecdh_private_key, server_public_key_obj)
                        logging.debug(
                            f"Received KEY_EXCHANGE_RESPONSE. Derived ChannelSK via ECDH: {channel_sk.hex()[:16]}...")
                        key_exchange_complete.set()
                    except Exception as e:
                        logging.error(f"Failed to process KEY_EXCHANGE_RESPONSE: {e}", exc_info=True)
                        console.print(f"! Error processing server's key: {e}", style="error")
                        key_exchange_complete.set()
                else:
                    logging.warning("Received KEY_EXCHANGE_RESPONSE but client ECDH state not ready.")
                continue

            if not channel_sk:
                logging.warning(f"Received non-key-exchange message but no ChannelSK: '{message_str}'")
                continue

            try:
                decrypted_payload_bytes = crypto_utils.decrypt_aes_gcm(channel_sk, message_str)
                payload = crypto_utils.deserialize_payload(decrypted_payload_bytes)
                logging.debug(f"Decrypted payload from server: {payload}")

                msg_type = payload.get("type")
                msg_status = payload.get("status")
                msg_detail = payload.get("detail", "")

                if msg_type == "AUTH_RESPONSE":  # For SECURE_SIGNUP
                    if msg_status == "SIGNUP_OK":
                        console.print(
                            "<Server> Signup successful! You can now signin.",
                            style="server",
                            markup=False,
                        )
                    elif msg_status == "SIGNUP_FAIL":
                        console.print(
                            f"<Server> Signup failed: {msg_detail}",
                            style="error",
                            markup=False,
                        )
                    else:
                        console.print(
                            f"<Server> Unexpected signup response: {msg_status}: {msg_detail}",
                            style="error",
                            markup=False,
                        )

                elif msg_type == "AUTH_CHALLENGE":
                    auth_challenge_data = {
                        "challenge": payload.get("challenge"), "salt": payload.get("salt"),
                        "iterations": payload.get("pbkdf2_iterations", crypto_utils.PBKDF2_ITERATIONS),
                        "key_length": payload.get("pbkdf2_key_length", crypto_utils.PBKDF2_KEY_LENGTH)
                    }
                    if not (auth_challenge_data["challenge"] and auth_challenge_data["salt"]):
                        console.print(
                            "\n<Server> Received incomplete auth challenge.",
                            style="error",
                            markup=False,
                        )
                        auth_challenge_data = None
                    else:
                        logging.debug(f"Auth challenge received: {auth_challenge_data['challenge'][:10]}...")
                        console.print(
                            "\n<Server> Authentication challenge received. Please provide password when prompted.",
                            style="server",
                            markup=False,
                        )

                elif msg_type == "AUTH_RESULT":
                    if payload.get("success"):
                        is_authenticated = True
                        console.print(
                            f"<Server> Welcome, {client_username}!",
                            style="server",
                            markup=False,
                        )
                    else:
                        is_authenticated = False
                        client_username = None
                        console.print(
                            f"<Server> Signin failed: {msg_detail}",
                            style="error",
                            markup=False,
                        )
                    auth_successful_event.set()

                elif msg_type == "GREETING_RESPONSE":
                    if payload.get("status") == "GREETING_OK":
                        console.print(
                            f"<Server> Greeting acknowledged! {msg_detail}",
                            style="server",
                            markup=False,
                        )
                    else:
                        console.print(
                            f"<Server> Greeting response: {payload.get('status')} - {msg_detail}",
                            style="server",
                            markup=False,
                        )

                elif msg_type == "SECURE_MESSAGE_INCOMING":
                    console.print(
                        f"<Secure Msg from {payload.get('from_user', 'Unknown')} ({payload.get('timestamp', '?')})> {payload.get('content', '')}",
                        style="server",
                        markup=False,
                    )
                elif msg_type == "BROADCAST_INCOMING":
                    console.print(
                        f"<Secure Bcast from {payload.get('from_user', 'Unknown')} ({payload.get('timestamp', '?')})> {payload.get('content', '')}",
                        style="server",
                        markup=False,
                    )
                elif msg_type == "MESSAGE_STATUS":
                    console.print(
                        f"<Server> {payload.get('status')}: {msg_detail}",
                        style="server",
                        markup=False,
                    )
                elif msg_type == "SERVER_ERROR":
                    console.print(
                        f"<Server> Error: {msg_detail}",
                        style="error",
                        markup=False,
                    )
                else:
                    logging.warning(f"Received unknown encrypted message type from server: {msg_type}")
                    console.print(
                        f"<Server> Unknown type {msg_type}: {msg_detail}",
                        style="error",
                        markup=False,
                    )

            except ValueError as e:  # Decryption or JSON decode failed
                logging.error(f"Failed to decrypt/decode server message: {e}. Msg snippet: {message_str[:50]}...")
                console.print(
                    "\n<System> Error processing message from server. It might be corrupted or keys desynced.",
                    style="error",
                    markup=False,
                )
            except Exception as e:
                logging.error(f"Generic error processing encrypted server message: {e}", exc_info=True)
                console.print(
                    f"\n<System> Unexpected error processing server message: {e}",
                    style="error",
                    markup=False,
                )

            if not stop_event.is_set():
                console.print(custom_prompt, end="", style="system")

        except socket.timeout:
            continue
        except UnicodeDecodeError as e:  # Should be rare now as server sends b64 or DH_RESPONSE
            logging.error(f"UnicodeDecodeError from server (unexpected format): {e}")
        except socket.error as e:
            if not stop_event.is_set():
                logging.error(f"Socket error in receive_messages: {e}")
            break  # Exit thread on socket error
        except Exception as e:
            if not stop_event.is_set():
                logging.error(
                    f"Unexpected error in receive_messages: {e}", exc_info=True
                )
            break
    logging.info("Receive thread stopped.")  # INFO for thread lifecycle


def send_secure_command_to_server(sock, server_address, command_type_header, payload_dict):
    global channel_sk
    if not channel_sk:
        console.print("! Cannot send command: Secure channel not established.", style="error")
        return
    try:
        plaintext_bytes = crypto_utils.serialize_payload(payload_dict)
        b64_encrypted_blob = crypto_utils.encrypt_aes_gcm(channel_sk, plaintext_bytes)
        final_message_to_send = f"{command_type_header.upper()}:{b64_encrypted_blob}"
        logging.debug(
            f"Sending to server {server_address}: '{command_type_header.upper()}:<blob len {len(b64_encrypted_blob)}>'")
        sock.sendto(final_message_to_send.encode('utf-8'), server_address)
    except Exception as e:
        console.print(f"\n! Error sending secure command '{command_type_header}': {e}", style="error")
        logging.error(f"Error sending secure command '{command_type_header}': {e}", exc_info=True)


def client_main_loop(sock, server_address):
    global is_authenticated, client_username, channel_sk, auth_challenge_data, auth_successful_event

    if not perform_key_exchange(sock, server_address):
        logging.critical(
            "Terminating client due to ECDH key exchange failure.")  # CRITICAL for unrecoverable setup issues
        # print("! Secure channel (ECDH) could not be established. Exiting.") # perform_key_exchange already prints
        stop_event.set()
        return

    print_command_list()
    while not stop_event.is_set():
        try:
            action_input = session.prompt(
                custom_prompt,
                completer=command_completer,
                is_password=False,
                validator=None,
            ).strip()
            if not action_input:
                continue
            action_parts = action_input.split(" ", 1)
            action_cmd = action_parts[0].lower()

            if not action_cmd:
                continue

            if action_cmd == "signup":
                uname = prompt_username("Enter username for signup: ")
                pword = session.prompt(
                    "Enter password for signup: ",
                    is_password=True,
                    validator=None,
                ).strip()
                if not uname or not pword:
                    console.print(
                        "<System> Username/password cannot be empty.",
                        style="error",
                        markup=False,
                    )
                else:
                    payload = {
                        "username": uname,
                        "password": pword,
                        "nonce": generate_nonce(),
                    }
                    send_secure_command_to_server(
                        sock, server_address, "SECURE_SIGNUP", payload
                    )
                    console.print(
                        f"<System> Signing up as {uname}...",
                        style="system",
                        markup=False,
                    )
                print_command_list()

            elif action_cmd == "signin":
                uname = prompt_username("Enter username for signin: ")
                pword = session.prompt(
                    "Enter password for signin: ",
                    is_password=True,
                    validator=None,
                ).strip()
                if not uname or not pword:
                    console.print(
                        "<System> Username/password cannot be empty.",
                        style="error",
                        markup=False,
                    )
                    continue

                client_username = uname
                auth_challenge_data = None
                auth_successful_event.clear()
                send_secure_command_to_server(sock, server_address, "AUTH_REQUEST", {"username": uname})
                console.print(
                    f"<System> Signing in as {uname}...",
                    style="system",
                    markup=False,
                )

                wait_start = time.time()
                while auth_challenge_data is None and time.time() - wait_start < 5 and not stop_event.is_set():
                    time.sleep(0.1)

                if auth_challenge_data:
                    try:
                        salt_bytes = bytes.fromhex(auth_challenge_data["salt"])
                        derived_key = crypto_utils.derive_password_verifier(pword, salt_bytes)
                        client_proof_bytes = crypto_utils.compute_hmac_sha256(derived_key, auth_challenge_data["challenge"])
                        proof_b64 = base64.b64encode(client_proof_bytes).decode("utf-8")
                        send_secure_command_to_server(sock, server_address, "AUTH_RESPONSE", {"challenge_response": proof_b64, "client_nonce": generate_nonce()})
                        wait_start = time.time()
                        while not auth_successful_event.is_set() and time.time() - wait_start < 5 and not stop_event.is_set():
                            time.sleep(0.1)
                        if not auth_successful_event.is_set():
                            console.print(
                                "<Server> Signin failed: no response from server",
                                style="error",
                                markup=False,
                            )
                            client_username = None
                    except Exception as e:
                        console.print(
                            f"<System> Error: {e}",
                            style="error",
                            markup=False,
                        )
                        logging.error(f"Client-side challenge processing error: {e}", exc_info=True)
                        client_username = None
                else:
                    console.print(
                        "<Server> Signin failed: challenge timeout",
                        style="error",
                        markup=False,
                    )
                    client_username = None
                print_command_list()

            elif action_cmd == "message":
                if not is_authenticated:
                    console.print(
                        "<System> Error: not signed in. Type `help` for usage.",
                        style="error",
                        markup=False,
                    )
                else:
                    parts = action_input.split(" ", 2)
                    if len(parts) > 2 and parts[2].strip():
                        target_user, msg_content = parts[1], parts[2]
                        payload = {"to_user": target_user, "content": msg_content, "timestamp": str(time.time())}
                        send_secure_command_to_server(sock, server_address, "SECURE_MESSAGE", payload)
                        console.print(
                            f"<You> to {target_user}: {msg_content}",
                            style="client",
                            markup=False,
                        )
                    else:
                        console.print(
                            "<System> Error: usage message <target> <content>. Type `help` for usage.",
                            style="error",
                            markup=False,
                        )

            elif action_cmd == "broadcast":
                if not is_authenticated:
                    console.print(
                        "<System> Error: not signed in. Type `help` for usage.",
                        style="error",
                        markup=False,
                    )
                else:
                    parts = action_input.split(" ", 1)
                    if len(parts) > 1 and parts[1].strip():
                        msg_content = parts[1]
                        payload = {"content": msg_content, "timestamp": str(time.time())}
                        send_secure_command_to_server(sock, server_address, "BROADCAST", payload)
                        console.print(
                            f"<You> broadcast: {msg_content}",
                            style="client",
                            markup=False,
                        )
                    else:
                        console.print(
                            "<System> Error: usage broadcast <content>. Type `help` for usage.",
                            style="error",
                            markup=False,
                        )

            elif action_cmd == "greet":
                if not is_authenticated:
                    console.print(
                        "<System> Error: not signed in. Type `help` for usage.",
                        style="error",
                        markup=False,
                    )
                else:
                    send_secure_command_to_server(sock, server_address, "GREET", {"nonce": generate_nonce()})
                    console.print(
                        "<You> greeting sent",
                        style="client",
                        markup=False,
                    )

            elif action_cmd == "help":
                console.print(
                    "signup      Sign up with a new username and password\n"
                    "signin      Log in with your credentials\n"
                    "message     Send a private message: message <target> <content>\n"
                    "broadcast   Send a message to all users: broadcast <content>\n"
                    "greet       Send a friendly greeting\n"
                    "logs        Show chat history\n"
                    "exit        Quit the application",
                    style="system",
                    markup=False,
                )

            elif action_cmd == "logs":
                try:
                    with open('client.log', 'r') as logf:
                        console.pager(logf.read())
                except FileNotFoundError:
                    console.print(
                        "<System> No log file found.",
                        style="error",
                        markup=False,
                    )
                    print_command_list()

            elif action_cmd == "exit":
                console.print("Exiting...", style="system")
            else:
                console.print(
                    f"<System> Error: unknown command '{action_input}'. Type `help` for usage.",
                    style="error",
                    markup=False,
                )
                print_command_list()

        except EOFError:
            stop_event.set()
        except KeyboardInterrupt:
            stop_event.set()
        except Exception as e:
            logging.error(f"Error in client main loop: {e}", exc_info=True)
            console.print(
                f"<System> An unexpected error occurred: {e}",
                style="error",
                markup=False,
            )

    logging.info("Client main loop stopped.")  # INFO for thread lifecycle


if __name__ == "__main__":
    if len(sys.argv) != 3:
        console.print(
            "Usage: python chat_client_secure.py <server_ip> <server_port>",
            style="system",
            markup=False,
        )
        sys.exit(1)
    server_ip_arg, server_port_arg_str = sys.argv[1], sys.argv[2]
    try:
        server_port_arg = int(server_port_arg_str)
        if not 1024 < server_port_arg < 65536:
            raise ValueError("Port must be 1025-65535")
    except ValueError as e:
        console.print(
            f"Invalid port: {e}",
            style="error",
            markup=False,
        )

    server_addr_tuple = (server_ip_arg, server_port_arg)
    client_sock = None
    receiver_thread = None  # Define for finally block
    try:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        logging.info(f"Client socket created for {server_addr_tuple}")  # INFO for setup
        receiver_thread = threading.Thread(target=receive_messages, args=(client_sock,), daemon=True)
        receiver_thread.start()
        client_main_loop(client_sock, server_addr_tuple)
    except socket.error as se:
        logging.critical(f"Client socket error during setup: {se}", exc_info=True)
        console.print(
            f"<System> Network error: {se}. Could not connect or communicate.",
            style="error",
            markup=False,
        )
    except Exception as e:
        logging.critical(f"Client critical setup error: {e}", exc_info=True)
        console.print(
            f"<System> A critical error occurred during client startup: {e}",
            style="error",
            markup=False,
        )
    finally:
        logging.info("Client shutting down...")  # INFO for shutdown sequence
        console.print(
            "<System> Shutting down client...",
            style="system",
            markup=False,
        )
        stop_event.set()
        if client_sock:
            client_sock.close()
        if receiver_thread and receiver_thread.is_alive():
            logging.debug("Waiting for receiver thread to join...")
            receiver_thread.join(timeout=1.0)  # Shorter timeout for cleanup
            if receiver_thread.is_alive():
                logging.warning("Receiver thread did not join cleanly during shutdown.")
        logging.info("Client shutdown complete.")
