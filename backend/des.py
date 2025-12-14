# des.py
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def des_encrypt(data: bytes, key: bytes, mode: str) -> bytes:
    """
    Chiffre les données avec DES.

    Args:
        data (bytes): données à chiffrer
        key (bytes): clé (8 octets)
        mode (str): mode de chiffrement ('ECB', 'CFB')

    Returns:
        bytes: données chiffrées
    """
    key = key.ljust(8, b'\0')[:8]  # DES utilise 8 octets
    if mode.upper() == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(data, DES.block_size))
    elif mode.upper() == "CFB":
        cipher = DES.new(key, DES.MODE_CFB)
        ciphertext = cipher.encrypt(data)
    else:
        raise ValueError(f"Mode DES inconnu: {mode}")

    return ciphertext

def des_decrypt(data: bytes, key: bytes, mode: str) -> bytes:
    """
    Déchiffre les données avec DES.

    Args:
        data (bytes): données à déchiffrer
        key (bytes): clé (8 octets)
        mode (str): mode de chiffrement ('ECB', 'CFB')

    Returns:
        bytes: données déchiffrées
    """
    key = key.ljust(8, b'\0')[:8]
    if mode.upper() == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(data), DES.block_size)
    elif mode.upper() == "CFB":
        cipher = DES.new(key, DES.MODE_CFB)
        plaintext = cipher.decrypt(data)
    else:
        raise ValueError(f"Mode DES inconnu: {mode}")

    return plaintext
