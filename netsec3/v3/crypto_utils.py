# crypto_utils.py
import os
import json
import base64
import hmac  # For HMAC
import hashlib  # For HMAC's SHA256, and PBKDF2's default
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec  # For Elliptic Curve
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# --- Elliptic Curve Diffie-Hellman (ECDH) Parameters ---
# We will use the SECP384R1 curve, a standard NIST curve offering good security.
# Other common choices include SECP256R1 (faster, still very secure) or X25519 (modern, good properties).
# For this assignment, SECP384R1 is a strong choice.
ECDH_CURVE = ec.SECP384R1()


def generate_ecdh_keys():
    """Generates ECDH private and public keys using the predefined curve."""
    private_key = ec.generate_private_key(ECDH_CURVE, default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_ecdh_public_key(public_key):
    """Serializes an ECDH public key to bytes (uncompressed point format) then base64 encodes it."""
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,  # Standard encoding for EC keys
        format=serialization.PublicFormat.UncompressedPoint  # Common format
    )
    return base64.b64encode(public_bytes).decode('utf-8')


def deserialize_ecdh_public_key(b64_encoded_key):
    """Deserializes a base64 encoded ECDH public key bytes."""
    public_bytes = base64.b64decode(b64_encoded_key)
    # Load using the curve, as the bytes are just the point representation
    return ec.EllipticCurvePublicKey.from_encoded_point(ECDH_CURVE, public_bytes)


def derive_shared_key_ecdh(private_key, peer_public_key):
    """Derives a shared AES key from ECDH key exchange using HKDF."""
    # Perform the ECDH key exchange to get the shared secret point
    shared_secret_ecdh = private_key.exchange(ec.ECDH(), peer_public_key)

    # Use HKDF to derive a 256-bit key for AES from the ECDH shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=None,  # Optional salt, can be omitted or derived from nonces
        info=b'ecdh handshake data for client-server session key',  # Context-specific info
        backend=default_backend()
    ).derive(shared_secret_ecdh)
    return derived_key  # This is the ChannelSK


# --- AES-GCM Encryption/Decryption ---
AES_KEY_SIZE = 32
AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16  # Though AESGCM handles this internally


def encrypt_aes_gcm(key, plaintext_bytes, associated_data=None):
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes long.")
    aesgcm = AESGCM(key)
    nonce = os.urandom(AES_GCM_NONCE_SIZE)
    ad = associated_data if associated_data else b''
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, ad)
    encrypted_blob = nonce + ciphertext_with_tag
    return base64.b64encode(encrypted_blob).decode('utf-8')


def encrypt_aes_gcm_with_nonce(key, nonce, plaintext_bytes, associated_data=None):
    """Encrypt using AES-GCM with caller-supplied nonce, returning base64 blob."""
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes long.")
    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError(f"Nonce must be {AES_GCM_NONCE_SIZE} bytes long.")
    aesgcm = AESGCM(key)
    ad = associated_data if associated_data else b''
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, ad)
    return base64.b64encode(nonce + ciphertext_with_tag).decode('utf-8')


def decrypt_aes_gcm(key, b64_encrypted_blob, associated_data=None):
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes long.")
    encrypted_blob_bytes = base64.b64decode(b64_encrypted_blob)
    nonce = encrypted_blob_bytes[:AES_GCM_NONCE_SIZE]
    ciphertext_with_tag = encrypted_blob_bytes[AES_GCM_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    ad = associated_data if associated_data else b''
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, ad)
        return plaintext_bytes
    except Exception as e:  # Handles InvalidTag from cryptography library
        raise ValueError("Decryption failed. Ciphertext may have been tampered or key is incorrect.") from e


def encrypt_aes_gcm_detached(key, nonce, plaintext_bytes, associated_data=None):
    """Encrypt with AES-GCM returning only ciphertext+tag as base64."""
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes long.")
    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError(f"Nonce must be {AES_GCM_NONCE_SIZE} bytes long.")
    aesgcm = AESGCM(key)
    ad = associated_data if associated_data else b''
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, ad)
    return base64.b64encode(ciphertext_with_tag).decode('utf-8')


def decrypt_aes_gcm_detached(key, nonce, b64_ciphertext, associated_data=None):
    """Decrypt AES-GCM ciphertext when nonce is transmitted separately."""
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes long.")
    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError(f"Nonce must be {AES_GCM_NONCE_SIZE} bytes long.")
    ciphertext_with_tag = base64.b64decode(b64_ciphertext)
    aesgcm = AESGCM(key)
    ad = associated_data if associated_data else b''
    try:
        return aesgcm.decrypt(nonce, ciphertext_with_tag, ad)
    except Exception as e:
        raise ValueError("Decryption failed. Ciphertext may have been tampered or key is incorrect.") from e


# --- Password Hashing & Challenge-Response Utilities ---
PBKDF2_ITERATIONS = 260000
PBKDF2_KEY_LENGTH = 32
PBKDF2_HASH_ALGORITHM = hashes.SHA256()


def generate_salt(size=16):
    return os.urandom(size)


def derive_password_verifier(password, salt):
    if isinstance(password, str):
        password = password.encode('utf-8')
    # Ensure salt is bytes
    if isinstance(salt, str):
        try:
            salt = bytes.fromhex(salt)
        except ValueError:  # If not hex, assume it's a string to be encoded
            salt = salt.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=PBKDF2_HASH_ALGORITHM,
        length=PBKDF2_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    derived_key = kdf.derive(password)
    return derived_key


def compute_hmac_sha256(key, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    # Key should be bytes
    return hmac.new(key, data, hashlib.sha256).digest()


# --- Serialization for Payloads --- (Remains the same)
def serialize_payload(payload_dict):
    return json.dumps(payload_dict).encode('utf-8')


def deserialize_payload(payload_bytes):
    return json.loads(payload_bytes.decode('utf-8'))


if __name__ == '__main__':
    # --- Test ECDH Key Exchange ---
    print("Testing ECDH Key Exchange...")
    # Party A (e.g., Client)
    priv_a_ec, pub_a_ec_obj = generate_ecdh_keys()
    pub_a_ec_b64 = serialize_ecdh_public_key(pub_a_ec_obj)
    print(f"Party A ECDH Public Key (b64): {pub_a_ec_b64[:40]}...")

    # Party B (e.g., Server)
    priv_b_ec, pub_b_ec_obj = generate_ecdh_keys()
    pub_b_ec_b64 = serialize_ecdh_public_key(pub_b_ec_obj)
    print(f"Party B ECDH Public Key (b64): {pub_b_ec_b64[:40]}...")

    # Simulate exchange
    # Party A receives Party B's public key
    received_pub_b_ec_obj = deserialize_ecdh_public_key(pub_b_ec_b64)
    shared_key_a_ec = derive_shared_key_ecdh(priv_a_ec, received_pub_b_ec_obj)
    print(f"Party A Derived Shared Key (ChannelSK from ECDH): {shared_key_a_ec.hex()}")

    # Party B receives Party A's public key
    received_pub_a_ec_obj = deserialize_ecdh_public_key(pub_a_ec_b64)
    shared_key_b_ec = derive_shared_key_ecdh(priv_b_ec, received_pub_a_ec_obj)
    print(f"Party B Derived Shared Key (ChannelSK from ECDH): {shared_key_b_ec.hex()}")

    assert shared_key_a_ec == shared_key_b_ec, "ECDH derived shared keys do not match!"
    print("ECDH Key Exchange Test Successful!\n")

    channel_sk_ecdh = shared_key_a_ec  # This would be the ChannelSK

    # --- Test AES-GCM Encryption/Decryption (using ECDH derived key) ---
    print("Testing AES-GCM Encryption/Decryption with ECDH key...")
    original_payload = {"message": "Hello, ECDH secure world!", "id": 456}
    original_plaintext_bytes = serialize_payload(original_payload)
    print(f"Original Plaintext: {original_payload}")

    b64_encrypted_ec = encrypt_aes_gcm(channel_sk_ecdh, original_plaintext_bytes)
    print(f"Base64 Encrypted Blob (AES with ECDH key): {b64_encrypted_ec[:50]}...")

    try:
        decrypted_plaintext_bytes_ec = decrypt_aes_gcm(channel_sk_ecdh, b64_encrypted_ec)
        decrypted_payload_ec = deserialize_payload(decrypted_plaintext_bytes_ec)
        print(f"Decrypted Plaintext: {decrypted_payload_ec}")
        assert original_payload == decrypted_payload_ec, "Decrypted payload does not match original!"
        print("AES-GCM (with ECDH key) Test Successful!\n")
    except ValueError as e:
        print(f"AES-GCM (with ECDH key) Test Failed: {e}")

    # --- Test Challenge-Response Utilities --- (Remains the same)
    print("Testing Challenge-Response Utilities...")
    # ... (previous challenge-response test code can be kept here) ...
    password_cr = "userStr0ngPasswordCR!"
    salt_bytes_cr = generate_salt()
    password_verifier_cr = derive_password_verifier(password_cr, salt_bytes_cr)
    server_challenge_str_cr = "unique_server_challenge_nonce_cr_67890"
    client_derived_key_cr = derive_password_verifier(password_cr, salt_bytes_cr)
    client_proof_bytes_cr = compute_hmac_sha256(client_derived_key_cr, server_challenge_str_cr)
    expected_proof_bytes_cr = compute_hmac_sha256(password_verifier_cr, server_challenge_str_cr)
    assert client_proof_bytes_cr == expected_proof_bytes_cr, "Challenge-response proof mismatch!"
    print("Challenge-Response Utilities Test Successful!\n")

    print("All crypto utils tests completed.")
