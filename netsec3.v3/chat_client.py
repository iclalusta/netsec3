# chat_client_secure.py
import socket
import sys
import threading
import time
import getpass
import uuid
import logging
import base64

try:
    import crypto_utils
except ImportError:
    print("Error: crypto_utils.py not found. Make sure it's in the same directory.")
    sys.exit(1)

# Configure logging: WARNING level for user-friendliness, DEBUG for troubleshooting
# To see DEBUG logs, change level=logging.DEBUG temporarily
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - CLIENT - %(levelname)s - %(message)s')

stop_event = threading.Event()
is_authenticated = False
client_username = None

client_ecdh_private_key = None
channel_sk = None
key_exchange_complete = threading.Event()

auth_challenge_data = None
auth_successful_event = threading.Event()


def generate_nonce():
    nonce = str(uuid.uuid4())
    logging.debug(f"Client generated nonce: {nonce}")
    return nonce


def perform_key_exchange(sock, server_address):
    global client_ecdh_private_key, channel_sk, key_exchange_complete
    logging.debug("Initiating ECDH Key Exchange...")
    try:
        client_ecdh_private_key, client_public_key_obj = crypto_utils.generate_ecdh_keys()
        client_ecdh_public_key_b64 = crypto_utils.serialize_ecdh_public_key(client_public_key_obj)
        key_exchange_init_message = f"DH_INIT:{client_ecdh_public_key_b64}"
        sock.sendto(key_exchange_init_message.encode('utf-8'), server_address)
        logging.debug(
            f"Sent KEY_EXCHANGE_INIT (DH_INIT protocol msg) to server with ECDH pubkey: {client_ecdh_public_key_b64[:30]}...")

        print("<System> Attempting to establish secure channel with server...")
        if not key_exchange_complete.wait(timeout=10.0):
            logging.warning("KEY_EXCHANGE_RESPONSE timeout. Server did not respond or message lost.")
            print("! Secure channel setup failed: Server did not respond in time.")
            return False

        if channel_sk:
            logging.info("ECDH Key Exchange Successful. ChannelSK established.")  # Keep as INFO for this critical step
            print("<System> Secure channel established with server via ECDH.")
            return True
        else:
            logging.error("Key exchange completed event set, but ChannelSK not derived.")
            print("! Secure channel setup failed: Could not derive shared key.")
            return False
    except Exception as e:
        logging.error(f"Error during ECDH Key Exchange: {e}", exc_info=True)
        print(f"! Secure channel setup failed: {e}")
        return False


def receive_messages(sock):
    global is_authenticated, client_username, client_ecdh_private_key, channel_sk, key_exchange_complete, auth_challenge_data, auth_successful_event
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
                        print(f"! Error processing server's key: {e}")
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
                        print(f"\n<Server> Signup successful! {msg_detail}")
                    elif msg_status == "SIGNUP_FAIL":
                        print(f"\n<Server> Signup failed: {msg_detail}")
                    else:
                        print(f"\n<Server Unexpected Auth Response> {msg_status}: {msg_detail}")

                elif msg_type == "AUTH_CHALLENGE":
                    auth_challenge_data = {
                        "challenge": payload.get("challenge"), "salt": payload.get("salt"),
                        "iterations": payload.get("pbkdf2_iterations", crypto_utils.PBKDF2_ITERATIONS),
                        "key_length": payload.get("pbkdf2_key_length", crypto_utils.PBKDF2_KEY_LENGTH)
                    }
                    if not (auth_challenge_data["challenge"] and auth_challenge_data["salt"]):
                        print("\n<Server> Received incomplete auth challenge.")
                        auth_challenge_data = None
                    else:
                        logging.debug(f"Auth challenge received: {auth_challenge_data['challenge'][:10]}...")
                        print("\n<Server> Authentication challenge received. Please provide password when prompted.")

                elif msg_type == "AUTH_RESULT":
                    if payload.get("success"):
                        is_authenticated = True
                        print(f"\n<Server> Signin successful! Welcome {client_username}. {msg_detail}")
                    else:
                        is_authenticated = False
                        client_username = None
                        print(f"\n<Server> Signin failed: {msg_detail}")
                    auth_successful_event.set()

                elif msg_type == "GREETING_RESPONSE":
                    if payload.get("status") == "GREETING_OK":
                        print(f"\n<Server> Greeting acknowledged! {msg_detail}")
                    else:
                        print(f"\n<Server> Greeting response: {payload.get('status')} - {msg_detail}")

                elif msg_type == "SECURE_MESSAGE_INCOMING":
                    print(
                        f"\n<Secure Msg from {payload.get('from_user', 'Unknown')} ({payload.get('timestamp', '?')})> {payload.get('content', '')}")
                elif msg_type == "BROADCAST_INCOMING":
                    print(
                        f"\n<Secure Bcast from {payload.get('from_user', 'Unknown')} ({payload.get('timestamp', '?')})> {payload.get('content', '')}")
                elif msg_type == "MESSAGE_STATUS":
                    print(f"\n<Server Msg Status> {payload.get('status')}: {msg_detail}")
                elif msg_type == "SERVER_ERROR":
                    print(f"\n<Server Secure Error> {msg_detail}")
                else:
                    logging.warning(f"Received unknown encrypted message type from server: {msg_type}")
                    print(f"\n<Server Encrypted - Unknown Type> Type: {msg_type}, Detail: {msg_detail}")

            except ValueError as e:  # Decryption or JSON decode failed
                logging.error(f"Failed to decrypt/decode server message: {e}. Msg snippet: {message_str[:50]}...")
                print("\n<System> Error processing message from server. It might be corrupted or keys desynced.")
            except Exception as e:
                logging.error(f"Generic error processing encrypted server message: {e}", exc_info=True)
                print(f"\n<System> Unexpected error processing server message: {e}")

            if not stop_event.is_set():
                print("] ", end='', flush=True)

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
        print("! Cannot send command: Secure channel not established.")
        return
    try:
        plaintext_bytes = crypto_utils.serialize_payload(payload_dict)
        b64_encrypted_blob = crypto_utils.encrypt_aes_gcm(channel_sk, plaintext_bytes)
        final_message_to_send = f"{command_type_header.upper()}:{b64_encrypted_blob}"
        logging.debug(
            f"Sending to server {server_address}: '{command_type_header.upper()}:<blob len {len(b64_encrypted_blob)}>'")
        sock.sendto(final_message_to_send.encode('utf-8'), server_address)
    except Exception as e:
        print(f"\n! Error sending secure command '{command_type_header}': {e}")
        logging.error(f"Error sending secure command '{command_type_header}': {e}", exc_info=True)


def client_main_loop(sock, server_address):
    global is_authenticated, client_username, channel_sk, auth_challenge_data, auth_successful_event

    if not perform_key_exchange(sock, server_address):
        logging.critical(
            "Terminating client due to ECDH key exchange failure.")  # CRITICAL for unrecoverable setup issues
        # print("! Secure channel (ECDH) could not be established. Exiting.") # perform_key_exchange already prints
        stop_event.set()
        return

    print("\nAvailable commands: signup, signin, message <target> <content>, broadcast <content>, greet, exit")
    while not stop_event.is_set():
        try:
            action_input = input("] ").strip()
            action_parts = action_input.lower().split(" ", 1)
            action_cmd = action_parts[0]

            if not action_cmd:
                continue

            if action_cmd == "signup":
                uname = input("Enter username for signup: ").strip()
                pword = getpass.getpass("Enter password for signup: ").strip()
                if uname and pword:
                    payload = {"username": uname, "password": pword, "nonce": generate_nonce()}
                    send_secure_command_to_server(sock, server_address, "SECURE_SIGNUP", payload)
                else:
                    print("Username and password cannot be empty.")

            elif action_cmd == "signin":
                uname = input("Enter username for signin: ").strip()
                if uname:
                    client_username = uname
                    auth_challenge_data = None
                    auth_successful_event.clear()
                    payload_step_a = {"username": uname}
                    send_secure_command_to_server(sock, server_address, "AUTH_REQUEST", payload_step_a)
                    print(f"<System> Sign-in request sent for {uname}. Waiting for server challenge...")

                    wait_start = time.time()
                    while auth_challenge_data is None and (time.time() - wait_start < 10) and not stop_event.is_set():
                        time.sleep(0.1)  # Wait for receive_messages to populate auth_challenge_data

                    if auth_challenge_data:
                        pword = getpass.getpass(
                            f"Enter password for {uname} (to respond to server challenge): ").strip()
                        if pword:
                            try:
                                salt_bytes = bytes.fromhex(auth_challenge_data["salt"])
                                derived_key = crypto_utils.derive_password_verifier(pword, salt_bytes)
                                client_proof_bytes = crypto_utils.compute_hmac_sha256(derived_key,
                                                                                      auth_challenge_data["challenge"])
                                client_proof_b64 = base64.b64encode(client_proof_bytes).decode('utf-8')
                                payload_step_c = {"challenge_response": client_proof_b64,
                                                  "client_nonce": generate_nonce()}
                                send_secure_command_to_server(sock, server_address, "AUTH_RESPONSE", payload_step_c)
                                print("<System> Challenge response sent. Waiting for final authentication result...")
                                if not auth_successful_event.wait(timeout=10.0):
                                    print(
                                        "<System> Sign-in final response timeout from server."
                                    )
                                    if not is_authenticated:
                                        client_username = None  # Reset if not successful
                            except Exception as e:
                                print(f"<System> Error processing challenge or creating response: {e}")
                                logging.error(f"Client-side challenge processing error: {e}", exc_info=True)
                                client_username = None
                        else:
                            print("Password cannot be empty for challenge response.")
                    elif not stop_event.is_set():  # Only print if not exiting
                        print(f"<System> Did not receive challenge from server for {uname} or timed out.")
                        client_username = None
                else:
                    print("Username cannot be empty for signin.")

            elif action_cmd == "message":
                if not is_authenticated:
                    print("You must be signed in to send messages.")
                parts = action_input.split(" ", 2)
                if len(parts) > 2:
                    target_user, msg_content = parts[1], parts[2]
                    if msg_content:
                        payload = {"to_user": target_user, "content": msg_content, "timestamp": str(time.time())}
                        send_secure_command_to_server(sock, server_address, "SECURE_MESSAGE", payload)
                    else:
                        print("Cannot send an empty message.")
                else:
                    print("Usage: message <target_user> <content>")

            elif action_cmd == "broadcast":
                if not is_authenticated:
                    print("You must be signed in to broadcast messages.")
                parts = action_input.split(" ", 1)
                if len(parts) > 1:
                    msg_content = parts[1]
                    if msg_content:
                        payload = {"content": msg_content, "timestamp": str(time.time())}
                        send_secure_command_to_server(sock, server_address, "BROADCAST", payload)
                    else:
                        print("Cannot send an empty broadcast message.")
                else:
                    print("Usage: broadcast <content>")

            elif action_cmd == "greet":
                if not is_authenticated:
                    print("You must be signed in to send GREETING.")
                send_secure_command_to_server(sock, server_address, "GREET", {"nonce": generate_nonce()})
                print("Sent GREET to server (securely).")

            elif action_cmd == "exit":
                print("Exiting...")
            else:
                print(f"Unknown command: '{action_input}'. Type 'help' for commands (if implemented).")

        except EOFError:
            stop_event.set()
        except KeyboardInterrupt:
            stop_event.set()
        except Exception as e:
            logging.error(f"Error in client main loop: {e}", exc_info=True)
            print(f"<System> An unexpected error occurred: {e}")

    logging.info("Client main loop stopped.")  # INFO for thread lifecycle


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python chat_client_secure.py <server_ip> <server_port>")
        sys.exit(1)
    server_ip_arg, server_port_arg_str = sys.argv[1], sys.argv[2]
    try:
        server_port_arg = int(server_port_arg_str)
        if not 1024 < server_port_arg < 65536:
            raise ValueError("Port must be 1025-65535")
    except ValueError as e:
        print(f"Invalid port: {e}")

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
        print(f"<System> Network error: {se}. Could not connect or communicate.")
    except Exception as e:
        logging.critical(f"Client critical setup error: {e}", exc_info=True)
        print(f"<System> A critical error occurred during client startup: {e}")
    finally:
        logging.info("Client shutting down...")  # INFO for shutdown sequence
        print("<System> Shutting down client...")
        stop_event.set()
        if client_sock:
            client_sock.close()
        if receiver_thread and receiver_thread.is_alive():
            logging.debug("Waiting for receiver thread to join...")
            receiver_thread.join(timeout=1.0)  # Shorter timeout for cleanup
            if receiver_thread.is_alive():
                logging.warning("Receiver thread did not join cleanly during shutdown.")
        logging.info("Client shutdown complete.")
