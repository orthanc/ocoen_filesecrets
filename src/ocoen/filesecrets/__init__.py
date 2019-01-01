from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto import Random

from ocoen.filesecrets import packer


def encrypt(data, password):
    kdf_alg = scrypt
    enc_alg = AES

    enc_info = {
        'kdf_alg': kdf_alg,
        'kdf_salt': Random.get_random_bytes(16),
        'kdf_options': {
            'key_len': 64,
            'N': 131072,
            'r': 8,
            'p': 1,
        },
        'enc_alg': enc_alg,
        'enc_mode': AES.MODE_SIV,
        'enc_options': {
            'nonce': Random.get_random_bytes(16),
        },
    }

    key = kdf_alg(password, enc_info['kdf_salt'], **enc_info['kdf_options'])
    cipher = enc_alg.new(key, enc_info['enc_mode'], **enc_info['enc_options'])
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return packer.pack(enc_info, ciphertext, tag)


def decrypt(packed, password):
    enc_info, ciphertext, tag = packer.unpack(packed)

    kdf_alg = enc_info['kdf_alg']
    enc_alg = enc_info['enc_alg']

    key = kdf_alg(password, enc_info['kdf_salt'], **enc_info['kdf_options'])
    cipher = enc_alg.new(key, enc_info['enc_mode'], **enc_info['enc_options'])
    return cipher.decrypt_and_verify(ciphertext, tag)
