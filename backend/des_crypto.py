# des_crypto.py
# Moteur DES (from-scratch) + modes ECB et CFB (CFB-64)
from typing import List
import os

BLOCK_SIZE = 8  # 64 bits

# --- Tables DES (IP/FP/E/P/PC1/PC2/S-Boxes) ---
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1
]

P = [
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
]

PC1 = [
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
]

PC2 = [
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
]

SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

S_BOX = [
    # S1
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    ],
    # S2
    [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    ],
    # S3
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    ],
    # S4
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    ],
    # S5
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    ],
    # S6
    [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    ],
    # S7
    [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    ],
    # S8
    [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ],
]

# --- utilitaires bits/bytes ---
def bytes_to_bits(b: bytes) -> List[int]:
    bits = []
    for byte in b:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits: List[int]) -> bytes:
    assert len(bits) % 8 == 0
    out = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for j in range(8):
            val = (val << 1) | bits[i + j]
        out.append(val)
    return bytes(out)

def permute(bits: List[int], table: List[int]) -> List[int]:
    return [bits[i - 1] for i in table]

def left_rotate(lst: List[int], n: int) -> List[int]:
    return lst[n:] + lst[:n]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# --- subkeys ---
def generate_subkeys(key8: bytes) -> List[List[int]]:
    if len(key8) != 8:
        raise ValueError("La clé DES doit contenir exactement 8 octets.")
    key_bits = bytes_to_bits(key8)
    permuted = permute(key_bits, PC1)
    C = permuted[:28]
    D = permuted[28:]
    subkeys = []
    for shift in SHIFTS:
        C = left_rotate(C, shift)
        D = left_rotate(D, shift)
        subkey = permute(C + D, PC2)
        subkeys.append(subkey)
    return subkeys

def feistel(R: List[int], subkey: List[int]) -> List[int]:
    expanded = permute(R, E)
    xored = [x ^ y for x, y in zip(expanded, subkey)]
    output_bits = []
    for i in range(8):
        chunk = xored[i*6:(i+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        s_val = S_BOX[i][row][col]
        for j in range(3, -1, -1):
            output_bits.append((s_val >> j) & 1)
    return permute(output_bits, P)

def des_block_encrypt(block8: bytes, subkeys: List[List[int]]) -> bytes:
    bits = bytes_to_bits(block8)
    bits = permute(bits, IP)
    L, R = bits[:32], bits[32:]
    for i in range(16):
        f_out = feistel(R, subkeys[i])
        L, R = R, [x ^ y for x, y in zip(L, f_out)]
    preoutput = R + L
    return bits_to_bytes(permute(preoutput, FP))

def des_block_decrypt(block8: bytes, subkeys: List[List[int]]) -> bytes:
    bits = bytes_to_bits(block8)
    bits = permute(bits, IP)
    L, R = bits[:32], bits[32:]
    for i in range(16):
        f_out = feistel(R, subkeys[15 - i])
        L, R = R, [x ^ y for x, y in zip(L, f_out)]
    preoutput = R + L
    return bits_to_bytes(permute(preoutput, FP))

# --- PKCS7 padding (pour ECB) ---
def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Longueur de données incorrecte pour le débourrage.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Bourrage invalide.")
    return data[:-pad_len]

# --- API : encrypt_data / decrypt_data ---
def encrypt_data(data: bytes, key: bytes, mode: str = "ECB", iv: bytes = None) -> bytes:
    mode = mode.upper()
    if len(key) != 8:
        raise ValueError("La clé DES doit contenir exactement 8 octets.")
    subkeys = generate_subkeys(key)

    if mode == "ECB":
        padded = pkcs7_pad(data, BLOCK_SIZE)
        out = bytearray()
        for i in range(0, len(padded), BLOCK_SIZE):
            out.extend(des_block_encrypt(padded[i:i+BLOCK_SIZE], subkeys))
        return bytes(out)
    elif mode == "CFB":
        if iv is None:
            iv = os.urandom(BLOCK_SIZE)
        if len(iv) != BLOCK_SIZE:
            raise ValueError("IV DES doit être de 8 octets.")
        out = bytearray()
        feedback = iv
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            keystream = des_block_encrypt(feedback, subkeys)
            x = xor_bytes(block, keystream[:len(block)])
            out.extend(x)
            if len(x) == BLOCK_SIZE:
                feedback = bytes(x)
            else:
                feedback = feedback[len(x):] + bytes(x)
        return iv + bytes(out)
    else:
        raise ValueError("Mode DES non supporté. Utilisez 'ECB' ou 'CFB'.")

def decrypt_data(data: bytes, key: bytes, mode: str = "ECB") -> bytes:
    mode = mode.upper()
    if len(key) != 8:
        raise ValueError("La clé DES doit contenir exactement 8 octets.")
    subkeys = generate_subkeys(key)

    if mode == "ECB":
        if len(data) % BLOCK_SIZE != 0:
            raise ValueError("Données chiffrées incorrectes (non multiple de 8) pour ECB.")
        out = bytearray()
        for i in range(0, len(data), BLOCK_SIZE):
            out.extend(des_block_decrypt(data[i:i+BLOCK_SIZE], subkeys))
        return pkcs7_unpad(bytes(out), BLOCK_SIZE)
    elif mode == "CFB":
        if len(data) < BLOCK_SIZE:
            raise ValueError("Données CFB trop courtes (doivent contenir IV).")
        iv = data[:BLOCK_SIZE]
        ciphertext = data[BLOCK_SIZE:]
        feedback = iv
        out = bytearray()
        for i in range(0, len(ciphertext), BLOCK_SIZE):
            block = ciphertext[i:i+BLOCK_SIZE]
            keystream = des_block_encrypt(feedback, subkeys)
            p = xor_bytes(block, keystream[:len(block)])
            out.extend(p)
            if len(block) == BLOCK_SIZE:
                feedback = bytes(block)
            else:
                feedback = feedback[len(block):] + bytes(block)
        return bytes(out)
    else:
        raise ValueError("Mode DES non supporté. Utilisez 'ECB' ou 'CFB'.")

# test quick
if __name__ == "__main__":
    k = b"12345678"
    m = b"Bonjour DES! test 123"
    c = encrypt_data(m, k, mode="ECB")
    assert decrypt_data(c, k, mode="ECB") == m
    c2 = encrypt_data(m, k, mode="CFB")
    assert decrypt_data(c2, k, mode="CFB") == m
    print("DES tests ok")
