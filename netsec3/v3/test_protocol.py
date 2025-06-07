import sys
import os
import unittest
import subprocess
import socket
import time
import uuid
import base64
try:
    from . import crypto_utils
except ImportError:
    import os
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    import crypto_utils


SERVER_PORT = 15000
SERVER_ADDR = ("127.0.0.1", SERVER_PORT)


def handshake(sock):
    private_key, public_key = crypto_utils.generate_ecdh_keys()
    pub_b64 = crypto_utils.serialize_ecdh_public_key(public_key)
    sock.sendto(f"DH_INIT:{pub_b64}".encode(), SERVER_ADDR)
    data, _ = sock.recvfrom(4096)
    assert data.startswith(b"DH_RESPONSE:")
    srv_pub_b64 = data.decode().split(":", 1)[1]
    srv_pub = crypto_utils.deserialize_ecdh_public_key(srv_pub_b64)
    channel_sk = crypto_utils.derive_shared_key_ecdh(private_key, srv_pub)
    return channel_sk


def send_command(sock, sk, cmd, payload):
    pt_bytes = crypto_utils.serialize_payload(payload)
    enc = crypto_utils.encrypt_aes_gcm(sk, pt_bytes)
    sock.sendto(f"{cmd}:{enc}".encode(), SERVER_ADDR)


def recv_payload(sock, sk):
    data, _ = sock.recvfrom(4096)
    decrypted = crypto_utils.decrypt_aes_gcm(sk, data.decode())
    return crypto_utils.deserialize_payload(decrypted)


def sign_up_and_sign_in(sock, sk, username, password):
    send_command(sock, sk, "SECURE_SIGNUP", {"username": username, "password": password})
    recv_payload(sock, sk)
    send_command(sock, sk, "AUTH_REQUEST", {"username": username})
    chal = recv_payload(sock, sk)
    salt = bytes.fromhex(chal["salt"])
    key = crypto_utils.derive_password_verifier(password, salt)
    proof = crypto_utils.compute_hmac_sha256(key, chal["challenge"])
    proof_b64 = base64.b64encode(proof).decode()
    send_command(
        sock,
        sk,
        "AUTH_RESPONSE",
        {"challenge_response": proof_b64, "client_nonce": str(uuid.uuid4())},
    )
    resp = recv_payload(sock, sk)
    assert resp.get("success")


class ChatProtocolTest(unittest.TestCase):
    def setUp(self):
        server_script = os.path.join(os.path.dirname(__file__), "chat_server.py")
        self.server = subprocess.Popen([
            sys.executable,
            server_script,
            str(SERVER_PORT),
        ])
        time.sleep(1.0)
        self.sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock1.settimeout(2)
        self.sock2.settimeout(2)
        self.sk1 = handshake(self.sock1)
        self.sk2 = handshake(self.sock2)

    def tearDown(self):
        self.sock1.close()
        self.sock2.close()
        self.server.terminate()
        self.server.wait(timeout=5)
        if os.path.exists("user_credentials_ecdh_cr.json"):
            os.remove("user_credentials_ecdh_cr.json")

    def test_full_flow(self):
        # Sign up users
        send_command(self.sock1, self.sk1, "SECURE_SIGNUP", {"username": "user1", "password": "password1"})
        resp = recv_payload(self.sock1, self.sk1)
        self.assertEqual(resp.get("status"), "SIGNUP_OK")
        send_command(self.sock2, self.sk2, "SECURE_SIGNUP", {"username": "user2", "password": "password2"})
        resp = recv_payload(self.sock2, self.sk2)
        self.assertEqual(resp.get("status"), "SIGNUP_OK")

        # Sign in user1
        send_command(self.sock1, self.sk1, "AUTH_REQUEST", {"username": "user1"})
        chal = recv_payload(self.sock1, self.sk1)
        salt = bytes.fromhex(chal["salt"])
        key = crypto_utils.derive_password_verifier("password1", salt)
        proof = crypto_utils.compute_hmac_sha256(key, chal["challenge"])
        proof_b64 = base64.b64encode(proof).decode()
        send_command(self.sock1, self.sk1, "AUTH_RESPONSE", {"challenge_response": proof_b64, "client_nonce": str(uuid.uuid4())})
        resp = recv_payload(self.sock1, self.sk1)
        self.assertTrue(resp.get("success"))

        # Sign in user2
        send_command(self.sock2, self.sk2, "AUTH_REQUEST", {"username": "user2"})
        chal2 = recv_payload(self.sock2, self.sk2)
        salt2 = bytes.fromhex(chal2["salt"])
        key2 = crypto_utils.derive_password_verifier("password2", salt2)
        proof2 = crypto_utils.compute_hmac_sha256(key2, chal2["challenge"])
        proof2_b64 = base64.b64encode(proof2).decode()
        send_command(self.sock2, self.sk2, "AUTH_RESPONSE", {"challenge_response": proof2_b64, "client_nonce": str(uuid.uuid4())})
        resp = recv_payload(self.sock2, self.sk2)
        self.assertTrue(resp.get("success"))

        # Direct message from user1 to user2
        send_command(self.sock1, self.sk1, "SECURE_MESSAGE", {"to_user": "user2", "content": "hi", "timestamp": str(time.time())})
        incoming = recv_payload(self.sock2, self.sk2)
        self.assertEqual(incoming.get("type"), "SECURE_MESSAGE_INCOMING")
        ack = recv_payload(self.sock1, self.sk1)
        self.assertEqual(ack.get("status"), "MESSAGE_SENT")

        # Broadcast from user2
        send_command(self.sock2, self.sk2, "BROADCAST", {"content": "hello all", "timestamp": str(time.time())})
        incoming_b = recv_payload(self.sock1, self.sk1)
        self.assertEqual(incoming_b.get("type"), "BROADCAST_INCOMING")
        ack_b = recv_payload(self.sock2, self.sk2)
        self.assertEqual(ack_b.get("status"), "BROADCAST_SENT")

    def test_oversized_message(self):
        sign_up_and_sign_in(self.sock1, self.sk1, "user1", "password1")
        sign_up_and_sign_in(self.sock2, self.sk2, "user2", "password2")

        long_msg = "x" * 513
        send_command(
            self.sock1,
            self.sk1,
            "SECURE_MESSAGE",
            {"to_user": "user2", "content": long_msg, "timestamp": str(time.time())},
        )
        ack = recv_payload(self.sock1, self.sk1)
        self.assertEqual(ack.get("status"), "MESSAGE_FAIL")

    def test_oversized_broadcast(self):
        sign_up_and_sign_in(self.sock1, self.sk1, "user1", "password1")
        sign_up_and_sign_in(self.sock2, self.sk2, "user2", "password2")

        long_msg = "y" * 513
        send_command(
            self.sock1,
            self.sk1,
            "BROADCAST",
            {"content": long_msg, "timestamp": str(time.time())},
        )
        ack = recv_payload(self.sock1, self.sk1)
        self.assertEqual(ack.get("status"), "BROADCAST_FAIL")


if __name__ == "__main__":
    unittest.main()
