from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto import Random

from ocoen.filesecrets import packer


def encrypt(data, password, authenticated_data=None):
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
        'enc_nonce': Random.get_random_bytes(16),
        'enc_options': {},
    }

    key = kdf_alg(password, enc_info['kdf_salt'], **enc_info['kdf_options'])
    cipher = enc_alg.new(key, enc_info['enc_mode'], nonce=enc_info['enc_nonce'], **enc_info['enc_options'])
    if authenticated_data:
        cipher.update(authenticated_data)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return packer.pack(enc_info, ciphertext, tag)


def decrypt(packed, password, authenticated_data=None):
    enc_info, ciphertext, tag = packer.unpack(packed)

    kdf_alg = enc_info['kdf_alg']
    enc_alg = enc_info['enc_alg']

    key = kdf_alg(password, enc_info['kdf_salt'], **enc_info['kdf_options'])
    cipher = enc_alg.new(key, enc_info['enc_mode'], nonce=enc_info['enc_nonce'], **enc_info['enc_options'])
    if authenticated_data:
        cipher.update(authenticated_data)
    return cipher.decrypt_and_verify(ciphertext, tag)
