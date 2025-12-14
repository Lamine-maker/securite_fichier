# des.py
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def des_encrypt(data: bytes, key: bytes, mode: str = "ECB") -> bytes:
    if len(key) != 8:
        raise ValueError("La clé DES doit faire 8 octets")
    
    cipher_mode = DES.MODE_ECB if mode.upper() == "ECB" else DES.MODE_CBC
    if cipher_mode == DES.MODE_CBC:
        from Crypto.Random import get_random_bytes
        iv = get_random_bytes(8)
        cipher = DES.new(key, cipher_mode, iv)
        encrypted = iv + cipher.encrypt(pad(data, 8))
    else:
        cipher = DES.new(key, cipher_mode)
        encrypted = cipher.encrypt(pad(data, 8))
    
    return encrypted

def des_decrypt(data: bytes, key: bytes, mode: str = "ECB") -> bytes:
    if len(key) != 8:
        raise ValueError("La clé DES doit faire 8 octets")
    
    cipher_mode = DES.MODE_ECB if mode.upper() == "ECB" else DES.MODE_CBC
    if cipher_mode == DES.MODE_CBC:
        iv = data[:8]
        encrypted_data = data[8:]
        cipher = DES.new(key, cipher_mode, iv)
        decrypted = unpad(cipher.decrypt(encrypted_data), 8)
    else:
        cipher = DES.new(key, cipher_mode)
        decrypted = unpad(cipher.decrypt(data), 8)
    
    return decrypted
