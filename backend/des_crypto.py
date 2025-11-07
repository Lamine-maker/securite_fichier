# des_crypto.py
from typing import List

BLOCK_SIZE = 8  # octets

# --- Tables standards DES ---
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

# PC-1 and PC-2 for key schedule
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

# Nombre de rotations pour chaque ronde
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# S-boxes (8 boxes)
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

# --- Helpers bitwise / conversion ---
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
    # table entries are 1-based
    return [bits[i - 1] for i in table]

def left_rotate(lst: List[int], n: int) -> List[int]:
    return lst[n:] + lst[:n]

def xor_bits(a: List[int], b: List[int]) -> List[int]:
    return [x ^ y for x, y in zip(a, b)]

# --- Key schedule ---
def generate_subkeys(key8: bytes) -> List[List[int]]:
    if len(key8) != 8:
        raise ValueError("La clé DES doit faire exactement 8 octets.")
    key_bits = bytes_to_bits(key8)  # 64 bits (includes parity bits)
    # Apply PC-1 -> 56 bits
    permuted = permute(key_bits, PC1)
    C = permuted[:28]
    D = permuted[28:]
    subkeys = []
    for shift in SHIFTS:
        C = left_rotate(C, shift)
        D = left_rotate(D, shift)
        CD = C + D
        subkey = permute(CD, PC2)  # 48 bits
        subkeys.append(subkey)
    return subkeys  # 16 subkeys (each 48 bits)

# --- The Feistel function f ---
def feistel(R: List[int], subkey: List[int]) -> List[int]:
    # Expand R from 32 to 48 bits using E
    expanded = permute(R, E)
    # XOR with subkey
    xored = xor_bits(expanded, subkey)
    # Split into eight 6-bit chunks and process through S-boxes
    output_bits = []
    for i in range(8):
        chunk = xored[i*6:(i+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        s_val = S_BOX[i][row][col]
        # convert s_val (0-15) to 4 bits
        for j in range(3, -1, -1):
            output_bits.append((s_val >> j) & 1)
    # Apply permutation P to the 32-bit result
    return permute(output_bits, P)

# --- Single-block encrypt/decrypt (64 bits) ---
def des_block_encrypt(block8: bytes, subkeys: List[List[int]]) -> bytes:
    bits = bytes_to_bits(block8)
    bits = permute(bits, IP)  # initial permutation
    L = bits[:32]
    R = bits[32:]
    for round_i in range(16):
        subkey = subkeys[round_i]
        f_out = feistel(R, subkey)
        newR = xor_bits(L, f_out)
        L = R
        R = newR
    # After 16 rounds, swap L and R (R then L) and apply final permutation
    preoutput = R + L
    final_bits = permute(preoutput, FP)
    return bits_to_bytes(final_bits)

def des_block_decrypt(block8: bytes, subkeys: List[List[int]]) -> bytes:
    # Decrypt by applying subkeys in reverse order
    bits = bytes_to_bits(block8)
    bits = permute(bits, IP)
    L = bits[:32]
    R = bits[32:]
    for round_i in range(16):
        subkey = subkeys[15 - round_i]
        f_out = feistel(R, subkey)
        newR = xor_bits(L, f_out)
        L = R
        R = newR
    preoutput = R + L
    final_bits = permute(preoutput, FP)
    return bits_to_bytes(final_bits)

# --- Padding PKCS#7 compatible with Crypto.Util.Padding ---
def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes.")
    return data[:-pad_len]

# --- API: mêmes signatures que l'original ---
def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Chiffre des données (ECB, PKCS#7) avec DES implémenté from-scratch.
    - data : octets quelconques
    - key  : 8 octets (64 bits, bits de parité inclus)
    Retourne : octets chiffrés (len multiple de 8)
    """
    if len(key) != 8:
        raise ValueError("La clé doit faire exactement 8 octets pour DES.")
    subkeys = generate_subkeys(key)
    padded = pkcs7_pad(data, BLOCK_SIZE)
    cipher_blocks = []
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i+BLOCK_SIZE]
        enc = des_block_encrypt(block, subkeys)
        cipher_blocks.append(enc)
    return b"".join(cipher_blocks)

def decrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Déchiffre des données (ECB, PKCS#7) avec DES from-scratch.
    - data : octets chiffrés, longueur multiple de 8
    - key  : 8 octets
    Retourne : octets clairs (padding PKCS#7 retiré)
    """
    if len(key) != 8:
        raise ValueError("La clé doit faire exactement 8 octets pour DES.")
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Les données chiffrées doivent être un multiple de 8 octets.")
    subkeys = generate_subkeys(key)
    plain_blocks = []
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        dec = des_block_decrypt(block, subkeys)
        plain_blocks.append(dec)
    padded_plain = b"".join(plain_blocks)
    return pkcs7_unpad(padded_plain, BLOCK_SIZE)

# --- Test rapide si le module est executé directement ---
if __name__ == "__main__":
    # test simple
    key = b"12345678"  # 8 bytes
    msg = b"Bonjour DES! test 123"  # longueur quelconque
    print("Key:", key)
    ct = encrypt_data(msg, key)
    print("Cipher (hex):", ct.hex())
    pt = decrypt_data(ct, key)
    print("Plain:", pt)
    assert pt == msg
    print("Auto-test OK.")
