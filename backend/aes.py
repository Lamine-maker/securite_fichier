# aes.py
# Wrapper AES using PyCryptodome: supports ECB and CFB (CFB with 128-bit segments)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Données invalides pour débourrage PKCS7.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Bourrage invalide.")
    return data[:-pad_len]

def encrypt_data(data: bytes, key: bytes, mode: str = "ECB", iv: bytes = None) -> bytes:
    mode = mode.upper()
    if len(key) not in (16,24,32):
        raise ValueError("La clé AES doit faire 16, 24 ou 32 octets.")
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pkcs7_pad(data, BLOCK_SIZE))
    elif mode == "CFB":
        if iv is None:
            iv = get_random_bytes(BLOCK_SIZE)
        if len(iv) != BLOCK_SIZE:
            raise ValueError("IV AES doit faire 16 octets.")
        cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
        ct = cipher.encrypt(data)
        return iv + ct
    else:
        raise ValueError("Mode AES non supporté. Utilisez 'ECB' ou 'CFB'.")

def decrypt_data(data: bytes, key: bytes, mode: str = "ECB") -> bytes:
    mode = mode.upper()
    if len(key) not in (16,24,32):
        raise ValueError("La clé AES doit faire 16, 24 ou 32 octets.")
    if mode == "ECB":
        if len(data) % BLOCK_SIZE != 0:
            raise ValueError("Données AES ECB invalides (longueur non multiple de 16).")
        cipher = AES.new(key, AES.MODE_ECB)
        return pkcs7_unpad(cipher.decrypt(data), BLOCK_SIZE)
    elif mode == "CFB":
        if len(data) < BLOCK_SIZE:
            raise ValueError("Données CFB AES trop courtes (doivent contenir IV).")
        iv = data[:BLOCK_SIZE]
        ct = data[BLOCK_SIZE:]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
        return cipher.decrypt(ct)
    else:
        raise ValueError("Mode AES non supporté. Utilisez 'ECB' ou 'CFB'.")

if __name__ == "__main__":
    k = b"thisis16bytes!!"
    m = b"Test message AES"
    assert decrypt_data(encrypt_data(m,k,"ECB"), k, "ECB") == m
    assert decrypt_data(encrypt_data(m,k,"CFB"), k, "CFB") == m
    print("AES tests ok")
