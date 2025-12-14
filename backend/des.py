from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 8

def des_encrypt(input_file, output_file, key, mode):
    data = open(input_file, 'rb').read()
    key = key.ljust(8, b'\0')[:8]

    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)
        encrypted = cipher.encrypt(pad(data, BLOCK_SIZE))
        open(output_file, 'wb').write(encrypted)

    elif mode == "CFB":
        iv = get_random_bytes(8)
        cipher = DES.new(key, DES.MODE_CFB, iv=iv)
        encrypted = iv + cipher.encrypt(data)
        open(output_file, 'wb').write(encrypted)

def des_decrypt(input_file, output_file, key, mode):
    data = open(input_file, 'rb').read()
    key = key.ljust(8, b'\0')[:8]

    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(data), BLOCK_SIZE)
        open(output_file, 'wb').write(decrypted)

    elif mode == "CFB":
        iv = data[:8]
        cipher = DES.new(key, DES.MODE_CFB, iv=iv)
        decrypted = cipher.decrypt(data[8:])
        open(output_file, 'wb').write(decrypted)
