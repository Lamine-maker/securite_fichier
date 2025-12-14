# aes.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(data: bytes, key: bytes, mode: str) -> bytes:
    key = key.ljust(16, b'\0')[:16]  # s'assurer que la clé fait 16 octets

    if mode.upper() == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
    elif mode.upper() == "CFB":
        cipher = AES.new(key, AES.MODE_CFB)
        ciphertext = cipher.encrypt(data)
    else:
        raise ValueError(f"Mode AES inconnu: {mode}")

    return ciphertext

def aes_decrypt(data: bytes, key: bytes, mode: str) -> bytes:
    key = key.ljust(16, b'\0')[:16]

    if mode.upper() == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(data), AES.block_size)
    elif mode.upper() == "CFB":
        cipher = AES.new(key, AES.MODE_CFB)
        plaintext = cipher.decrypt(data)
    else:
        raise ValueError(f"Mode AES inconnu: {mode}")

    return plaintext
