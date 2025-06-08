import os
import socket
import subprocess
import sys
import time
import base64
import uuid
import json

from . import crypto_utils

SERVER_PORT = 16000
SERVER_ADDR = ("127.0.0.1", SERVER_PORT)

NONCE_SIZE = crypto_utils.AES_GCM_NONCE_SIZE


def ecdh_handshake(sock):
    priv, pub = crypto_utils.generate_ecdh_keys()
    pub_b64 = crypto_utils.serialize_ecdh_public_key(pub)
    sock.sendto(f"DH_INIT:{pub_b64}".encode(), SERVER_ADDR)
    data, _ = sock.recvfrom(4096)
    assert data.startswith(b"DH_RESPONSE:")
    srv_pub = crypto_utils.deserialize_ecdh_public_key(data.decode().split(":", 1)[1])
    sk = crypto_utils.derive_shared_key_ecdh(priv, srv_pub)
    return sk


def send_cmd(sock, sk, cmd, payload):
    pt = crypto_utils.serialize_payload(payload)
    enc = crypto_utils.encrypt_aes_gcm(sk, pt)
    sock.sendto(f"{cmd}:{enc}".encode(), SERVER_ADDR)


def recv_payload(sock, sk):
    data, _ = sock.recvfrom(4096)
    dec = crypto_utils.decrypt_aes_gcm(sk, data.decode())
    return crypto_utils.deserialize_payload(dec)


def sign_up_and_in(sock, sk, username, password):
    send_cmd(sock, sk, "SECURE_SIGNUP", {"username": username, "password": password})
    recv_payload(sock, sk)
    send_cmd(sock, sk, "AUTH_REQUEST", {"username": username})
    chal = recv_payload(sock, sk)
    salt = bytes.fromhex(chal["salt"])
    key = crypto_utils.derive_password_verifier(password, salt)
    proof = crypto_utils.compute_hmac_sha256(key, chal["challenge"])
    send_cmd(
        sock,
        sk,
        "AUTH_RESPONSE",
        {
            "challenge_response": base64.b64encode(proof).decode(),
            "client_nonce": str(uuid.uuid4()),
        },
    )
    resp = recv_payload(sock, sk)
    assert resp.get("success")


def run_server():
    script = os.path.join(os.path.dirname(__file__), "chat_server.py")
    return subprocess.Popen([sys.executable, script, str(SERVER_PORT)])


def test_needham_schroeder_chat(tmp_path):
    server = run_server()
    time.sleep(1.0)
    try:
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock1.settimeout(2)
        sock2.settimeout(2)
        sk1 = ecdh_handshake(sock1)
        sk2 = ecdh_handshake(sock2)

        sign_up_and_in(sock1, sk1, "alice", "password1")
        sign_up_and_in(sock2, sk2, "bob", "password2")

        # NS_REQ from alice for bob
        nonce1 = base64.b64encode(os.urandom(NONCE_SIZE)).decode()
        plain_req = f"bob:{nonce1}".encode()
        enc_req = crypto_utils.encrypt_aes_gcm(sk1, plain_req)
        sock1.sendto(f"NS_REQ:{enc_req}".encode(), SERVER_ADDR)

        data, _ = sock1.recvfrom(4096)
        parts = data.decode().split(":", 2)
        assert parts[0] == "NS_RESP" and parts[1] == "bob"
        resp_plain = crypto_utils.decrypt_aes_gcm(sk1, parts[2])
        resp = json.loads(resp_plain.decode())
        assert resp["nonce1"] == nonce1
        kab = base64.b64decode(resp["K_AB"])
        ticket = resp["ticket"]

        # send ticket to bob
        nonce2 = os.urandom(NONCE_SIZE)
        enc_n2 = crypto_utils.encrypt_aes_gcm_with_nonce(kab, nonce2, nonce2)
        sock1.sendto(
            f"NS_TICKET:bob:alice:{ticket}:{enc_n2}".encode(), SERVER_ADDR
        )

        data, _ = sock2.recvfrom(4096)
        parts = data.decode().split(":", 4)
        assert parts[0] == "NS_TICKET" and parts[1] == "bob"
        ticket_plain = crypto_utils.decrypt_aes_gcm(sk2, parts[3])
        tdata = json.loads(ticket_plain.decode())
        assert tdata.get("sender") == "alice"
        kab2 = base64.b64decode(tdata["K_AB"])
        assert kab2 == kab
        nonce2_recv = crypto_utils.decrypt_aes_gcm(kab2, parts[4])
        assert nonce2_recv == nonce2

        nonce3 = os.urandom(NONCE_SIZE)
        n2_minus = (int.from_bytes(nonce2_recv, "big") - 1).to_bytes(NONCE_SIZE, "big")
        auth_payload = crypto_utils.encrypt_aes_gcm_with_nonce(
            kab2, nonce3, n2_minus + nonce3
        )
        sock2.sendto(
            f"NS_AUTH:alice:bob:{auth_payload}".encode(), SERVER_ADDR
        )

        data, _ = sock1.recvfrom(4096)
        parts = data.decode().split(":", 3)
        assert parts[0] == "NS_AUTH" and parts[2] == "bob"
        auth_plain = crypto_utils.decrypt_aes_gcm(kab, parts[3])
        n2_chk = auth_plain[:NONCE_SIZE]
        nonce3_recv = auth_plain[NONCE_SIZE:]
        assert n2_chk == n2_minus
        n3_minus = (int.from_bytes(nonce3_recv, "big") - 1).to_bytes(NONCE_SIZE, "big")
        fin_blob = crypto_utils.encrypt_aes_gcm_with_nonce(kab, nonce3_recv, n3_minus)
        sock1.sendto(
            f"NS_FIN:bob:alice:{fin_blob}".encode(), SERVER_ADDR
        )

        data, _ = sock2.recvfrom(4096)
        parts = data.decode().split(":", 3)
        assert parts[0] == "NS_FIN" and parts[1] == "bob"
        fin_plain = crypto_utils.decrypt_aes_gcm(kab2, parts[3])
        assert fin_plain == n3_minus

        # send chat message after handshake
        chat_nonce = os.urandom(NONCE_SIZE)
        chat_ct = crypto_utils.encrypt_aes_gcm_detached(kab, chat_nonce, b"hi")
        msg = f"CHAT:bob:alice:{base64.b64encode(chat_nonce).decode()}:{chat_ct}"
        sock1.sendto(msg.encode(), SERVER_ADDR)

        data, _ = sock2.recvfrom(4096)
        parts = data.decode().split(":", 4)
        assert parts[0] == "CHAT" and parts[2] == "alice"
        chat_pt = crypto_utils.decrypt_aes_gcm_detached(
            kab2, base64.b64decode(parts[3]), parts[4]
        )
        assert chat_pt == b"hi"
    finally:
        sock1.close()
        sock2.close()
        server.terminate()
        server.wait(timeout=5)
        if os.path.exists("user_credentials_ecdh_cr.json"):
            os.remove("user_credentials_ecdh_cr.json")
