from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16

def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_data(data: bytes, key: bytes, mode: str):
    mode = mode.upper()

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(data))
        return ciphertext, b""

    elif mode == "CFB":
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        ciphertext = cipher.encrypt(data)
        return ciphertext, iv

    else:
        raise ValueError("Mode AES invalide")

def decrypt_data(ciphertext: bytes, key: bytes, mode: str, iv: bytes):
    mode = mode.upper()

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext))

    elif mode == "CFB":
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        return cipher.decrypt(ciphertext)

    else:
        raise ValueError("Mode AES invalide")
