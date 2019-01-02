from Crypto import Random

from ocoen.filesecrets import cipher, kdf, packer


def encrypt(data, password, authenticated_data=None):
    kdf_alg = kdf.scrypt
    enc_alg = cipher.AES256_SIV

    enc_info = {
        'kdf_alg': kdf_alg,
        'kdf_salt': Random.get_random_bytes(kdf_alg.salt_length),
        'kdf_options': kdf_alg.default_options,
        'enc_alg': enc_alg,
        'enc_nonce': Random.get_random_bytes(enc_alg.nonce_length),
        'enc_options': enc_alg.default_options,
    }

    key = kdf_alg.derive_key(password, enc_info['kdf_salt'], enc_alg.key_length, **enc_info['kdf_options'])
    ciphertext, tag = enc_alg.encrypt_and_digest(data, authenticated_data, key, enc_info['enc_nonce'], **enc_info['enc_options'])

    return packer.pack(enc_info, ciphertext, tag)


def decrypt(packed, password, authenticated_data=None):
    enc_info, ciphertext, tag = packer.unpack(packed)

    kdf_alg = enc_info['kdf_alg']
    enc_alg = enc_info['enc_alg']

    key = kdf_alg.derive_key(password, enc_info['kdf_salt'], enc_alg.key_length, **enc_info['kdf_options'])
    return enc_alg.decrypt_and_verify(ciphertext, tag, authenticated_data, key, enc_info['enc_nonce'], **enc_info['enc_options'])
