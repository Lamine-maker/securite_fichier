from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib


BLOCK_SIZE = 16


def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()[:16]


def encrypt(data: bytes, password: str, mode: str) -> bytes:
    key = derive_key(password)

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(data, BLOCK_SIZE))

    elif mode == "CFB":
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        return iv + cipher.encrypt(data)

    else:
        raise ValueError("Mode AES invalide")


def decrypt(data: bytes, password: str, mode: str) -> bytes:
    key = derive_key(password)

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(data), BLOCK_SIZE)

    elif mode == "CFB":
        iv = data[:BLOCK_SIZE]
        ciphertext = data[BLOCK_SIZE:]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        return cipher.decrypt(ciphertext)

    else:
        raise ValueError("Mode AES invalide")
