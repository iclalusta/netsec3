# chat_server_secure.py
import socket
import sys
import logging
import json
import os
import time
import base64
import hmac
import re
from collections import defaultdict

try:
    from . import crypto_utils
except ImportError:
    import os
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    try:
        import crypto_utils
    except ImportError:
        print("Error: crypto_utils.py not found.")
        sys.exit(1)

# Configure logging: INFO level for server operations
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - SERVER - %(levelname)s - %(message)s",
)

CREDENTIALS_FILE = "user_credentials_ecdh_cr.json"
MAX_REQUESTS_PER_WINDOW = 20
REQUEST_WINDOW_SECONDS = 60
INTERNAL_NONCE_EXPIRY_SECONDS = 300
TIMESTAMP_WINDOW_SECONDS = 60
MAX_MSG_LENGTH = 512

user_credentials_cr = {}
client_sessions = {}
request_tracker = defaultdict(list)
used_internal_nonces = {}

# Regular expression for allowed usernames
USERNAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,15}$")


def validate_username_format(username):
    """Return True if the username matches the allowed format."""
    return isinstance(username, str) and bool(USERNAME_PATTERN.fullmatch(username))


def validate_password_format(password):
    """Return True if the password meets length requirements."""
    return isinstance(password, str) and 6 <= len(password) <= 128


def validate_message_content(content):
    """Return True if message content length is within allowed bounds."""
    return isinstance(content, str) and 0 < len(content) <= MAX_MSG_LENGTH


def validate_broadcast_content(content):
    """Return True if broadcast content length is within allowed bounds."""
    return isinstance(content, str) and 0 < len(content) <= MAX_MSG_LENGTH


def load_cr_credentials():
    global user_credentials_cr
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r') as f:
                user_credentials_cr = json.load(f)
            logging.info(f"Loaded {len(user_credentials_cr)} user(s) from {CREDENTIALS_FILE}")
        except Exception as e:
            logging.error(f"Load CR creds fail: {e}. Starting empty.")
    else:
        logging.info(f"{CREDENTIALS_FILE} not found. Starting empty.")
        user_credentials_cr = {}


def save_cr_credentials():
    try:
        with open(CREDENTIALS_FILE, 'w') as f:
            json.dump(user_credentials_cr, f, indent=4)
        logging.info(f"Saved CR user credentials to {CREDENTIALS_FILE}")
    except Exception as e:
        logging.error(f"Save CR creds fail: {e}")


def is_rate_limited(ip_address):
    current_time = time.time()
    request_tracker[ip_address] = [ts for ts in request_tracker[ip_address] if
                                   current_time - ts < REQUEST_WINDOW_SECONDS]
    if len(request_tracker[ip_address]) >= MAX_REQUESTS_PER_WINDOW:
        logging.warning(f"Rate limit exceeded for IP: {ip_address}")
        return True
    request_tracker[ip_address].append(current_time)
    return False


def validate_internal_nonce(nonce_value):
    current_time = time.time()
    global used_internal_nonces
    used_internal_nonces = {n: ts for n, ts in used_internal_nonces.items() if
                            current_time - ts < INTERNAL_NONCE_EXPIRY_SECONDS}
    if nonce_value in used_internal_nonces:
        logging.warning(f"Internal nonce reuse attempt: '{nonce_value}'")
        return False  # More specific log
    used_internal_nonces[nonce_value] = current_time
    logging.debug(f"Internal nonce validated: {nonce_value}")
    return True


def validate_timestamp_internal(timestamp_str):
    try:
        if abs(time.time() - float(timestamp_str)) <= TIMESTAMP_WINDOW_SECONDS:
            return True
        logging.warning(
            f"Invalid internal timestamp: {timestamp_str}. Diff: {abs(time.time() - float(timestamp_str))}")
        return False
    except ValueError:
        logging.warning(f"Malformed internal timestamp: {timestamp_str}")
        return False


def validate_username_password_format(username, password):
    """Validate both username and password formats."""
    if not validate_username_format(username):
        return False, (
            "Username must start with a letter and contain only letters, "
            "numbers or '_' (3-16 chars)"
        )
    if not validate_password_format(password):
        return False, "Password must be 6-128 chars."
    return True, ""


def send_encrypted_response(sock, client_address, channel_sk, response_payload_dict):
    if not channel_sk:
        logging.error(
            f"No ChannelSK for {client_address}. Cannot send encrypted response."
        )
    try:
        plaintext_bytes = crypto_utils.serialize_payload(response_payload_dict)
        b64_encrypted_blob = crypto_utils.encrypt_aes_gcm(channel_sk, plaintext_bytes)
        sock.sendto(b64_encrypted_blob.encode('utf-8'), client_address)
        logging.debug(
            f"Sent encrypted to {client_address}: Type {response_payload_dict.get('type')}, Success {response_payload_dict.get('success')}, Detail: {response_payload_dict.get('detail', '')[:30]}...")
    except Exception as e:
        logging.error(f"Error sending encrypted response to {client_address}: {e}", exc_info=True)


def server(port):
    """Run the UDP chat server on the given port."""
    load_cr_credentials()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', port))
        logging.info(f"Secure ECDH+CR server started on port {port}...")
    except Exception as e:
        logging.critical(f"Server startup error: {e}", exc_info=True)

    while True:
        try:
            data, client_addr = sock.recvfrom(4096)
            message_str = data.decode('utf-8')
            client_ip = client_addr[0]
            logging.debug(f"Raw from {client_addr}: '{message_str[:100]}...'")  # DEBUG for raw messages

            if is_rate_limited(client_ip):
                continue  # Rate limit log is already a WARNING

            parts = message_str.split(':', 1)
            command_header = parts[0]
            payload_b64_str = parts[1] if len(parts) > 1 else ""

            if command_header == "DH_INIT":
                logging.info(f"Processing KEY_EXCHANGE_INIT from {client_addr}")  # INFO for new connection attempt
                try:
                    client_ecdh_public_key_obj = crypto_utils.deserialize_ecdh_public_key(payload_b64_str)
                    server_ecdh_private_key, server_ecdh_public_key_obj = crypto_utils.generate_ecdh_keys()
                    channel_sk_derived = crypto_utils.derive_shared_key_ecdh(server_ecdh_private_key,
                                                                             client_ecdh_public_key_obj)
                    client_sessions[client_addr] = {
                        "channel_sk": channel_sk_derived, "username": None,
                        "authenticated_at": None, "last_seen": time.time(),
                        "pending_challenge": None
                    }
                    server_ecdh_public_key_b64 = crypto_utils.serialize_ecdh_public_key(server_ecdh_public_key_obj)
                    response_key_exchange = f"DH_RESPONSE:{server_ecdh_public_key_b64}"
                    sock.sendto(response_key_exchange.encode('utf-8'), client_addr)
                    logging.info(f"KEY_EXCHANGE successful with {client_addr}. Sent KEY_EXCHANGE_RESPONSE.")
                except Exception as e:
                    logging.error(f"Error during KEY_EXCHANGE_INIT from {client_addr}: {e}", exc_info=True)
                continue

            session = client_sessions.get(client_addr)
            if not session or not session.get("channel_sk"):
                logging.warning(
                    f"Command '{command_header}' from {client_addr} without established ChannelSK. Ignoring.")
                continue

            current_channel_sk = session["channel_sk"]
            session["last_seen"] = time.time()

            try:
                decrypted_payload_bytes = crypto_utils.decrypt_aes_gcm(current_channel_sk, payload_b64_str)
                req_payload = crypto_utils.deserialize_payload(decrypted_payload_bytes)
                logging.debug(
                    f"Decrypted payload from {client_addr} ({command_header}): {req_payload}")  # DEBUG for decrypted content
            except Exception as e:
                logging.warning(f"Payload decryption/decode failed for '{command_header}' from {client_addr}: {e}")
                send_encrypted_response(sock, client_addr, current_channel_sk,
                                        {"type": "SERVER_ERROR",
                                         "detail": "Payload decryption/decode failed. Please retry."})
                continue

            response_payload = {}

            if command_header == "SECURE_SIGNUP":
                username = req_payload.get("username")
                password = req_payload.get("password")
                logging.info(f"Processing SECURE_SIGNUP for username '{username}' from {client_addr}")
                response_payload["type"] = "AUTH_RESPONSE"
                is_valid, fmt_msg = validate_username_password_format(username, password)
                if not is_valid:
                    response_payload.update({"status": "SIGNUP_FAIL", "detail": fmt_msg})
                elif username in user_credentials_cr:
                    response_payload.update({"status": "SIGNUP_FAIL", "detail": "Username already exists."})
                else:
                    salt_b = crypto_utils.generate_salt()
                    verifier_b = crypto_utils.derive_password_verifier(password, salt_b)
                    user_credentials_cr[username] = {
                        "salt": salt_b.hex(), "verifier": verifier_b.hex(),
                        "pbkdf2_iterations": crypto_utils.PBKDF2_ITERATIONS,
                        "pbkdf2_key_length": crypto_utils.PBKDF2_KEY_LENGTH
                    }
                    save_cr_credentials()  # Logs success/failure internally
                    response_payload.update({"status": "SIGNUP_OK", "detail": "Signup successful. You can now signin."})
                    logging.info(f"SECURE_SIGNUP successful for '{username}' from {client_addr}")
                send_encrypted_response(sock, client_addr, current_channel_sk, response_payload)

            elif command_header == "AUTH_REQUEST":
                username = req_payload.get("username")
                logging.info(f"Processing AUTH_REQUEST for username '{username}' from {client_addr}")
                user_data = user_credentials_cr.get(username)
                if user_data:
                    server_challenge = crypto_utils.generate_salt(16).hex()
                    session["pending_challenge"] = server_challenge
                    session["pending_auth_username"] = username
                    challenge_payload = {"type": "AUTH_CHALLENGE", "challenge": server_challenge,
                                         "salt": user_data["salt"],
                                         "pbkdf2_iterations": user_data.get("pbkdf2_iterations",
                                                                            crypto_utils.PBKDF2_ITERATIONS),
                                         "pbkdf2_key_length": user_data.get("pbkdf2_key_length",
                                                                            crypto_utils.PBKDF2_KEY_LENGTH)}
                    send_encrypted_response(sock, client_addr, current_channel_sk, challenge_payload)
                    logging.info(f"Sent AUTH_CHALLENGE to '{username}'@{client_addr}")
                else:
                    logging.warning(f"AUTH_REQUEST for unknown user '{username}' from {client_addr}")
                    send_encrypted_response(sock, client_addr, current_channel_sk,
                                            {"type": "AUTH_RESULT", "success": False, "detail": "Username not found."})

            elif command_header == "AUTH_RESPONSE":
                client_proof_b64 = req_payload.get("challenge_response")
                client_req_nonce = req_payload.get("client_nonce")
                username = session.get("pending_auth_username")
                server_challenge = session.get("pending_challenge")
                user_data = user_credentials_cr.get(username) if username else None
                logging.info(f"Processing AUTH_RESPONSE for '{username}' from {client_addr}")

                auth_res_payload = {"type": "AUTH_RESULT", "success": False}
                if not (client_proof_b64 and client_req_nonce and username and server_challenge and user_data):
                    auth_res_payload["detail"] = "Invalid auth response or missing session state."
                    logging.warning(f"Invalid AUTH_RESPONSE from {client_addr} for user {username}: missing data.")
                elif not validate_internal_nonce(client_req_nonce):
                    auth_res_payload["detail"] = "Invalid or reused request token (nonce)."
                    # Log for this already in validate_internal_nonce
                else:
                    try:
                        client_proof_b = base64.b64decode(client_proof_b64)
                        verifier_b = bytes.fromhex(user_data["verifier"])
                        expected_proof_b = crypto_utils.compute_hmac_sha256(verifier_b, server_challenge)
                        if hmac.compare_digest(expected_proof_b, client_proof_b):
                            session["username"] = username
                            session["authenticated_at"] = time.time()
                            auth_res_payload.update({"success": True, "detail": f"Welcome back, {username}!"})
                            logging.info(f"Authentication SUCCESS for '{username}'@{client_addr}")
                        else:
                            auth_res_payload["detail"] = "Invalid credentials (proof mismatch)."
                            logging.warning(f"Authentication FAIL (proof mismatch) for '{username}'@{client_addr}")
                    except Exception as e:
                        auth_res_payload["detail"] = "Error verifying proof. Please try again."
                        logging.error(f"Error verifying proof for {username} from {client_addr}: {e}", exc_info=True)

                session["pending_challenge"] = None
                session["pending_auth_username"] = None
                send_encrypted_response(sock, client_addr, current_channel_sk, auth_res_payload)

            elif not session.get("username"):  # Check for authenticated commands below
                logging.warning(f"Unauthenticated command '{command_header}' from {client_addr}. Denying.")
                send_encrypted_response(sock, client_addr, current_channel_sk,
                                        {"type": "AUTH_RESULT", "success": False,
                                         "detail": "Not signed in. Please signin first."})

            elif command_header == "GREET":
                logging.info(f"Processing GREET from '{session['username']}'@{client_addr}")
                send_encrypted_response(sock, client_addr, current_channel_sk,
                                        {"type": "GREETING_RESPONSE", "status": "GREETING_OK",
                                         "detail": f"Hello {session['username']}! Greeting received."})

            elif command_header == "SECURE_MESSAGE":
                to_user = req_payload.get("to_user")
                content = req_payload.get("content")
                ts = req_payload.get("timestamp")
                sender = session["username"]
                logging.info(f"Processing SECURE_MESSAGE from '{sender}' to '{to_user}' via {client_addr}")
                status_payload = {"type": "MESSAGE_STATUS"}
                if not (validate_username_format(to_user) and validate_message_content(content) and validate_timestamp_internal(ts)):
                    status_payload.update({"status": "MESSAGE_FAIL", "detail": "Invalid message format or timestamp."})
                    logging.warning(f"Invalid SECURE_MESSAGE format from '{sender}': to={to_user}, ts={ts}")
                else:
                    target_addr, target_sk = None, None
                    for addr, s_data in client_sessions.items():  # Find recipient
                        if s_data.get("username") == to_user:
                            target_addr, target_sk = addr, s_data.get("channel_sk")
                    if target_addr and target_sk:
                        send_encrypted_response(sock, target_addr, target_sk,
                                                {"type": "SECURE_MESSAGE_INCOMING", "from_user": sender,
                                                 "content": content, "timestamp": ts})
                        status_payload.update(
                            {"status": "MESSAGE_SENT", "detail": f"Message successfully relayed to {to_user}."})
                        logging.info(f"Relayed SECURE_MESSAGE from '{sender}' to '{to_user}'@{target_addr}")
                    else:
                        status_payload.update(
                            {"status": "MESSAGE_FAIL", "detail": f"User '{to_user}' not found or is offline."})
                        logging.info(f"SECURE_MESSAGE from '{sender}' to offline/unknown user '{to_user}'")
                send_encrypted_response(sock, client_addr, current_channel_sk, status_payload)  # ACK to sender

            elif command_header == "BROADCAST":
                content = req_payload.get("content")
                ts = req_payload.get("timestamp")
                sender = session["username"]
                logging.info(f"Processing BROADCAST from '{sender}' via {client_addr}")
                status_payload = {"type": "MESSAGE_STATUS"}
                if not (validate_broadcast_content(content) and validate_timestamp_internal(ts)):
                    status_payload.update(
                        {"status": "BROADCAST_FAIL", "detail": "Invalid broadcast format or timestamp."})
                    logging.warning(f"Invalid BROADCAST format from '{sender}': ts={ts}")
                else:
                    count = 0
                    for addr, s_data in list(client_sessions.items()):
                        if addr != client_addr and s_data.get("username") and s_data.get("channel_sk"):
                            send_encrypted_response(sock, addr, s_data["channel_sk"],
                                                    {"type": "BROADCAST_INCOMING", "from_user": sender,
                                                     "content": content, "timestamp": ts})
                            count += 1
                    status_payload.update(
                        {"status": "BROADCAST_SENT", "detail": f"Broadcast sent to {count} other active users."})
                    logging.info(f"Relayed BROADCAST from '{sender}' to {count} other clients.")
                send_encrypted_response(sock, client_addr, current_channel_sk, status_payload)

            else:
                logging.warning(
                    f"Unknown authenticated command '{command_header}' from '{session.get('username', 'UNKNOWN')}'@{client_addr}")
                send_encrypted_response(sock, client_addr, current_channel_sk,
                                        {"type": "SERVER_ERROR",
                                         "detail": f"Unknown or unsupported command: {command_header}"})

        except ConnectionResetError:
            if client_addr in client_sessions:
                logging.info(
                    f"Client {client_sessions[client_addr].get('username', client_addr)} disconnected (ConnectionResetError). Session removed.")
                del client_sessions[client_addr]
            else:
                logging.warning(f"ConnectionResetError from {client_addr} (no active session).")
        except UnicodeDecodeError as ude:  # Should be less common now
            logging.error(f"UnicodeDecodeError from {client_addr}: {ude}. Raw data: {data[:60]}")
        except Exception as e:
            logging.error(f"Unexpected critical error processing data from {client_addr}: {e}", exc_info=True)
            s_err = client_sessions.get(client_addr)  # Attempt to send encrypted error if session exists
            if s_err and s_err.get("channel_sk"):
                send_encrypted_response(sock, client_addr, s_err["channel_sk"], {"type": "SERVER_ERROR",
                                                                                 "detail": "An unexpected internal server error occurred. Please try again."})


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python chat_server_secure.py <port>")
        sys.exit(1)
    try:
        server_port = int(sys.argv[1])
        if not 1024 < server_port < 65536:
            raise ValueError("Port must be 1025-65535")
        server(server_port)
    except ValueError as e:
        print(f"Invalid port: {e}")
    except KeyboardInterrupt:
        logging.info("Server shutting down by user interrupt (Ctrl+C)...")
    finally:
        logging.info("Server stopped.")
