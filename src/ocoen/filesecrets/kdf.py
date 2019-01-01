from abc import ABC, abstractmethod
from struct import Struct

import Crypto.Protocol.KDF


class _KDF(ABC):
    def __init__(self, id, salt_length, default_options):
        self.id = id
        self.salt_length = salt_length
        self.default_options = default_options

    @abstractmethod
    def derive_key(self, password, salt, key_length, **options):
        pass

    def pack_options(self, options):
        return b''

    def unpack_options(self, packed_options):
        assert len(packed_options) == 0
        return {}


class _Scrypt(_KDF):
    # key length
    # N
    # r
    # p
    OPTIONS_STRUCT = Struct('>LBB')

    def __init__(self):
        super().__init__(1, 16, {
                                    'N': 131072,
                                    'r': 8,
                                    'p': 1,
                                })

    def derive_key(self, password, salt, key_length, **options):
        return Crypto.Protocol.KDF.scrypt(password, salt, key_length, **options)

    def pack_options(self, options):
        return _Scrypt.OPTIONS_STRUCT.pack(options['N'], options['r'], options['p'])

    def unpack_options(self, packed_options):
        N, r, p = _Scrypt.OPTIONS_STRUCT.unpack(packed_options[0:_Scrypt.OPTIONS_STRUCT.size])
        return {
            'N': N,
            'r': r,
            'p': p,
        }


_by_id = {}


def by_id(id):
    return _by_id[id]


scrypt = _Scrypt()
_by_id[scrypt.id] = scrypt
