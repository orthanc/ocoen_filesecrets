from abc import ABC, abstractmethod

import Crypto.Cipher.AES


class _Cipher(ABC):
    def __init__(self, id, key_length, nonce_length, default_options):
        self.id = id
        self.key_length = key_length
        self.nonce_length = nonce_length
        self.default_options = default_options

    @abstractmethod
    def encrypt_and_digest(self, data, authenticated_data, key, nonce, **options):
        pass

    @abstractmethod
    def decrypt_and_verify(self, ciphertext, tag, authenticated_data, key, nonce, **options):
        pass

    def pack_options(self, options):
        return b''

    def unpack_options(self, packed_options):
        assert len(packed_options) == 0
        return {}


class _AES(_Cipher):

    def __init__(self, id, mode, key_length, nonce_key, nonce_length, default_options):
        super().__init__(id, key_length, nonce_length, default_options)
        self._mode = mode
        self._nonce_key = nonce_key

    def encrypt_and_digest(self, data, authenticated_data, key, nonce, **options):
        options_with_nonce = self._add_nonce(options, nonce)
        cipher = Crypto.Cipher.AES.new(key, self._mode, **options_with_nonce)
        if authenticated_data:
            cipher.update(authenticated_data)
        return cipher.encrypt_and_digest(data)

    def decrypt_and_verify(self, ciphertext, tag, authenticated_data, key, nonce, **options):
        options_with_nonce = self._add_nonce(options, nonce)
        cipher = Crypto.Cipher.AES.new(key, self._mode, **options_with_nonce)
        if authenticated_data:
            cipher.update(authenticated_data)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def _add_nonce(self, options, nonce):
        copy = options.copy()
        copy[self._nonce_key] = nonce
        return copy


_by_id = {}


def by_id(id):
    return _by_id[id]


AES256_SIV = _AES(1, Crypto.Cipher.AES.MODE_SIV, 64, 'nonce', 16, {})
_by_id[AES256_SIV.id] = AES256_SIV
