"""
hde_backend.py
HDE simulator: AES-256-GCM and RSA-2048 (hybrid) cryptographic functions.
"""
import os
import struct
import binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# ---------- AES helpers ----------
AES_KEY_BYTES = 32   # 256-bit
NONCE_BYTES = 12
TAG_BYTES = 16

def aes_generate_key() -> bytes:
    """Generates a random 256-bit AES key."""
    return get_random_bytes(AES_KEY_BYTES)

def aes_key_to_hex(key: bytes) -> str:
    """Converts a bytes key to a hexadecimal string representation."""
    return binascii.hexlify(key).decode()

def aes_hex_to_key(hexstr: str) -> bytes:
    """Converts a hexadecimal string back to a bytes key."""
    return binascii.unhexlify(hexstr.strip())

def aes_encrypt_file(in_path: str, out_path: str, key: bytes) -> None:
    """
    Encrypts a file using AES-256-GCM.
    The output file format is: [nonce (12)][tag (16)][ciphertext].
    """
    with open(in_path, "rb") as f:
        plaintext = f.read()
    nonce = get_random_bytes(NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    with open(out_path, "wb") as out_f:
        out_f.write(nonce)
        out_f.write(tag)
        out_f.write(ciphertext)

def aes_decrypt_file(in_path: str, out_path: str, key: bytes) -> None:
    """
    Decrypts a file encrypted with AES-256-GCM.
    The input format is expected to be: [nonce (12)][tag (16)][ciphertext].
    """
    with open(in_path, "rb") as f:
        data = f.read()
    if len(data) < NONCE_BYTES + TAG_BYTES:
        raise ValueError("Input data too short or corrupted (AES).")
    nonce = data[:NONCE_BYTES]
    tag = data[NONCE_BYTES:NONCE_BYTES+TAG_BYTES]
    ciphertext = data[NONCE_BYTES+TAG_BYTES:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    with open(out_path, "wb") as out_f:
        out_f.write(plaintext)

# ---------- RSA (hybrid) helpers ----------
RSA_KEY_SIZE = 2048

def rsa_generate_keypair():
    """Generates an RSA 2048-bit public/private keypair."""
    key = RSA.generate(RSA_KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt_file(in_path: str, out_path: str, pubkey_bytes: bytes) -> None:
    """
    Hybrid encryption: encrypts a file with a one-time AES session key,
    and then encrypts the session key with RSA.
    The output file format is:
    [2-byte len][rsa_encrypted_session_key][nonce][tag][ciphertext]
    """
    # 1) read plaintext
    with open(in_path, "rb") as f:
        plaintext = f.read()

    # 2) create random AES session key
    session_key = get_random_bytes(AES_KEY_BYTES)

    # 3) AES-GCM encrypt payload
    nonce = get_random_bytes(NONCE_BYTES)
    aes_cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)

    # 4) RSA encrypt session key
    pubkey = RSA.import_key(pubkey_bytes)
    rsa_cipher = PKCS1_OAEP.new(pubkey)
    enc_session_key = rsa_cipher.encrypt(session_key)

    # 5) write combined file
    L = len(enc_session_key)
    if L >= (1 << 16):
        raise ValueError("Encrypted session key too long.")
    with open(out_path, "wb") as out_f:
        out_f.write(struct.pack(">H", L))
        out_f.write(enc_session_key)
        out_f.write(nonce)
        out_f.write(tag)
        out_f.write(ciphertext)

def rsa_decrypt_file(in_path: str, out_path: str, privkey_bytes: bytes) -> None:
    """
    Hybrid decryption: decrypts the AES session key with the RSA private key,
    then uses the session key to decrypt the file payload.
    """
    with open(in_path, "rb") as f:
        data = f.read()

    if len(data) < 2:
        raise ValueError("Input data too short or corrupted (RSA hybrid).")

    L = struct.unpack(">H", data[:2])[0]
    pos = 2
    if len(data) < pos + L + NONCE_BYTES + TAG_BYTES:
        raise ValueError("Input data too short or corrupted (RSA hybrid lengths).")

    enc_session_key = data[pos:pos+L]; pos += L
    nonce = data[pos:pos+NONCE_BYTES]; pos += NONCE_BYTES
    tag = data[pos:pos+TAG_BYTES]; pos += TAG_BYTES
    ciphertext = data[pos:]

    # RSA-decrypt session key
    privkey = RSA.import_key(privkey_bytes)
    rsa_cipher = PKCS1_OAEP.new(privkey)
    session_key = rsa_cipher.decrypt(enc_session_key)

    # AES-GCM decrypt payload
    aes_cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)

    with open(out_path, "wb") as out_f:
        out_f.write(plaintext)
