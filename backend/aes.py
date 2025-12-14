# aes.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16  # AES block size

def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def encrypt_data(data: bytes, key: bytes, mode: str = "ECB") -> bytes:
    mode = mode.upper()
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(data))
    elif mode == "CFB":
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        return iv + cipher.encrypt(data)
    else:
        raise ValueError("Mode AES invalide (ECB ou CFB)")

def decrypt_data(data: bytes, key: bytes, mode: str = "ECB") -> bytes:
    mode = mode.upper()
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(data))
    elif mode == "CFB":
        iv = data[:BLOCK_SIZE]
        ciphertext = data[BLOCK_SIZE:]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        return cipher.decrypt(ciphertext)
    else:
        raise ValueError("Mode AES invalide (ECB ou CFB)")
