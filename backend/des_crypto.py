# des_crypto.py
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Chiffre des données avec DES"""
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(data, DES.block_size))

def decrypt_data(data: bytes, key: bytes) -> bytes:
    """Déchiffre des données avec DES"""
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(data), DES.block_size)
