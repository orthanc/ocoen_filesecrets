from struct import Struct

from Crypto import Cipher
from Crypto.Protocol import KDF

VERSION_1 = b'\x01'

# Fixed Block Size
# Enc Info Size
# Ciphertext Start
# Tag Size
FILE_INDEX_STRUCT = Struct('>BBHB')

# Fixed Block Size
# KDF Header Size
# ENC Header Size
ENC_INFO_STRUCT = Struct('>BBB')

# Algorithm Id
# Salt Length
# Options Length
KDF_HEADER_STRUCT = Struct('>BBB')

# key length
# N
# r
# p
SCRYPT_OPTIONS_STRUCT = Struct('>BLBB')

# Algorithm Id
# Nonce Length
# Options Length
ENC_HEADER_STRUCT = Struct('>BBB')

# nonce size
AES_SIV_OPTIONS_STRUCT = Struct('>B')


def pack(enc_info, ciphertext, tag):
    packed_enc_info = _pack_enc_info(enc_info)
    return (VERSION_1
            + FILE_INDEX_STRUCT.pack(FILE_INDEX_STRUCT.size, len(packed_enc_info), len(ciphertext), len(tag))
            + packed_enc_info
            + ciphertext
            + tag
            )


def unpack(packed):
    assert packed[0:1] == VERSION_1

    fixed_size, enc_info_size, ciphertext_size, tag_size = FILE_INDEX_STRUCT.unpack(packed[1:1 + FILE_INDEX_STRUCT.size])
    enc_info_start = 1 + fixed_size
    ciphertext_start = enc_info_start + enc_info_size
    tag_start = ciphertext_start + ciphertext_size

    enc_info = _unpack_enc_info(packed[enc_info_start:enc_info_start + enc_info_size])
    ciphertext = packed[ciphertext_start:ciphertext_start + ciphertext_size]
    tag = packed[tag_start:tag_start + tag_size]

    return enc_info, ciphertext, tag


def _pack_enc_info(enc_info):
    packed_kdf_header = _pack_kdf_header(enc_info['kdf_alg'], enc_info['kdf_salt'], enc_info['kdf_options'])
    packed_enc_header = _pack_enc_header(enc_info['enc_alg'], enc_info['enc_mode'], enc_info['enc_nonce'], enc_info['enc_options'])

    return (ENC_INFO_STRUCT.pack(ENC_INFO_STRUCT.size, len(packed_kdf_header), len(packed_enc_header))
            + packed_kdf_header
            + packed_enc_header
            )


def _unpack_enc_info(packed_enc_info):
    fixed_size, kdf_header_size, enc_header_size = ENC_INFO_STRUCT.unpack(packed_enc_info[0:ENC_INFO_STRUCT.size])
    kdf_header_start = fixed_size
    enc_header_start = kdf_header_start + kdf_header_size

    kdf_alg, kdf_salt, kdf_options = _unpack_kdf_header(packed_enc_info[kdf_header_start:kdf_header_start + kdf_header_size])
    enc_alg, enc_mode, enc_nonce, enc_options = _unpack_enc_header(packed_enc_info[enc_header_start:enc_header_start + enc_header_size])

    return {
        'kdf_alg': kdf_alg,
        'kdf_salt': kdf_salt,
        'kdf_options': kdf_options,
        'enc_alg': enc_alg,
        'enc_mode': enc_mode,
        'enc_nonce': enc_nonce,
        'enc_options': enc_options,
    }


def _pack_kdf_header(alg, salt, options):
    alg_id, option_packer = KDF_ALGS[alg]
    packed_options = option_packer(options)

    return (KDF_HEADER_STRUCT.pack(alg_id, len(salt), len(packed_options))
            + salt
            + packed_options
            )


def _unpack_kdf_header(packed_header):
    alg_id, salt_size, options_size = KDF_HEADER_STRUCT.unpack(packed_header[0:KDF_HEADER_STRUCT.size])
    salt_start = KDF_HEADER_STRUCT.size
    options_start = salt_start + salt_size

    alg, option_unpacker = KDF_ALGS_BY_ID[alg_id]
    salt = packed_header[salt_start:salt_start + salt_size]
    options = option_unpacker(packed_header[options_start:options_start + options_size])

    return alg, salt, options


def _pack_scrypt_options(options):
    return SCRYPT_OPTIONS_STRUCT.pack(options['key_len'], options['N'], options['r'], options['p'])


def _unpack_scrypt_options(packed_options):
    key_len, N, r, p = SCRYPT_OPTIONS_STRUCT.unpack(packed_options[0:SCRYPT_OPTIONS_STRUCT.size])
    return {
        'key_len': key_len,
        'N': N,
        'r': r,
        'p': p,
    }


def _pack_enc_header(alg, mode, nonce, options):
    alg_id, option_packer = ENC_ALGS[(alg, mode)]
    packed_options = option_packer(options)

    return (ENC_HEADER_STRUCT.pack(alg_id, len(nonce), len(packed_options))
            + nonce
            + packed_options
            )


def _unpack_enc_header(packed_header):
    alg_id, nonce_size, options_size = ENC_HEADER_STRUCT.unpack(packed_header[0:ENC_HEADER_STRUCT.size])
    nonce_start = ENC_HEADER_STRUCT.size
    options_start = nonce_start + nonce_size

    alg, mode, option_unpacker = ENC_ALGS_BY_ID[alg_id]
    nonce = packed_header[nonce_start:nonce_start + nonce_size]
    options = option_unpacker(packed_header[options_start:options_start + options_size])

    return alg, mode, nonce, options


def _pack_aes_siv_options(options):
    return b''


def _unpack_aes_siv_options(packed_options):
    return {}


KDF_ALGS = {
    KDF.scrypt: (1, _pack_scrypt_options),
}
KDF_ALGS_BY_ID = {
    1: (KDF.scrypt, _unpack_scrypt_options),
}

ENC_ALGS = {
    (Cipher.AES, Cipher.AES.MODE_SIV): (1, _pack_aes_siv_options),
}
ENC_ALGS_BY_ID = {
    1: (Cipher.AES, Cipher.AES.MODE_SIV, _unpack_aes_siv_options),
}
