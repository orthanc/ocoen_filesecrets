from Crypto import Random

from ocoen.filesecrets import cipher, kdf, packer


class Encrypter(object):
    def __init__(self, kdf_alg=kdf.scrypt, kdf_options=None, enc_alg=cipher.AES256_SIV, enc_options=None):
        self._kdf_alg = kdf_alg
        if kdf_options:
            self._kdf_options = kdf_options
        else:
            self._kdf_options = kdf_alg.default_options

        self._enc_alg = enc_alg
        if enc_options:
            self._enc_options = enc_options
        else:
            self._enc_options = enc_alg.default_options

    def encrypt(self, data, password, authenticated_data=None):
        enc_info = {
            'kdf_alg': self._kdf_alg,
            'kdf_salt': Random.get_random_bytes(self._kdf_alg.salt_length),
            'kdf_options': self._kdf_options,
            'enc_alg': self._enc_alg,
            'enc_nonce': Random.get_random_bytes(self._enc_alg.nonce_length),
            'enc_options': self._enc_options,
        }

        key = self._kdf_alg.derive_key(password, enc_info['kdf_salt'], self._enc_alg.key_length, **enc_info['kdf_options'])
        ciphertext, tag = self._enc_alg.encrypt_and_digest(data, authenticated_data, key, enc_info['enc_nonce'], **enc_info['enc_options'])

        return packer.pack(enc_info, ciphertext, tag)


_default_encrypter = Encrypter()
encrypt = _default_encrypter.encrypt


def decrypt(packed, password, authenticated_data=None):
    enc_info, ciphertext, tag = packer.unpack(packed)

    kdf_alg = enc_info['kdf_alg']
    enc_alg = enc_info['enc_alg']

    key = kdf_alg.derive_key(password, enc_info['kdf_salt'], enc_alg.key_length, **enc_info['kdf_options'])
    return enc_alg.decrypt_and_verify(ciphertext, tag, authenticated_data, key, enc_info['enc_nonce'], **enc_info['enc_options'])


def is_encrypted(data):
    return packer.get_format_version(data) is not None
