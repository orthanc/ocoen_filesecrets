from struct import Struct

from ocoen.filesecrets import cipher, kdf

VERSION_2 = b'\xf4\x5f\xff\x73'

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


# Algorithm Id
# Nonce Length
# Options Length
ENC_HEADER_STRUCT = Struct('>BBB')

# nonce size
AES_SIV_OPTIONS_STRUCT = Struct('>B')


def pack(enc_info, ciphertext, tag):
    packed_enc_info = _pack_enc_info(enc_info)
    return (VERSION_2
            + FILE_INDEX_STRUCT.pack(FILE_INDEX_STRUCT.size, len(packed_enc_info), len(ciphertext), len(tag))
            + packed_enc_info
            + ciphertext
            + tag
            )


def unpack(packed):
    start = _get_start_offset(packed)

    fixed_size, enc_info_size, ciphertext_size, tag_size = FILE_INDEX_STRUCT.unpack(packed[start:start + FILE_INDEX_STRUCT.size])
    enc_info_start = start + fixed_size
    ciphertext_start = enc_info_start + enc_info_size
    tag_start = ciphertext_start + ciphertext_size

    enc_info = _unpack_enc_info(packed[enc_info_start:enc_info_start + enc_info_size])
    ciphertext = packed[ciphertext_start:ciphertext_start + ciphertext_size]
    tag = packed[tag_start:tag_start + tag_size]

    return enc_info, ciphertext, tag


def get_format_version(packed):
    if packed[0:4] == VERSION_2:
        return 2
    else:
        None


def _get_start_offset(packed):
    version = get_format_version(packed)
    if version == 2:
        return 4
    else:
        raise ValueError('Unknown Format')


def _pack_enc_info(enc_info):
    packed_kdf_header = _pack_kdf_header(enc_info['kdf_alg'], enc_info['kdf_salt'], enc_info['kdf_options'])
    packed_enc_header = _pack_enc_header(enc_info['enc_alg'], enc_info['enc_nonce'], enc_info['enc_options'])

    return (ENC_INFO_STRUCT.pack(ENC_INFO_STRUCT.size, len(packed_kdf_header), len(packed_enc_header))
            + packed_kdf_header
            + packed_enc_header
            )


def _unpack_enc_info(packed_enc_info):
    fixed_size, kdf_header_size, enc_header_size = ENC_INFO_STRUCT.unpack(packed_enc_info[0:ENC_INFO_STRUCT.size])
    kdf_header_start = fixed_size
    enc_header_start = kdf_header_start + kdf_header_size

    kdf_alg, kdf_salt, kdf_options = _unpack_kdf_header(packed_enc_info[kdf_header_start:kdf_header_start + kdf_header_size])
    enc_alg, enc_nonce, enc_options = _unpack_enc_header(packed_enc_info[enc_header_start:enc_header_start + enc_header_size])

    return {
        'kdf_alg': kdf_alg,
        'kdf_salt': kdf_salt,
        'kdf_options': kdf_options,
        'enc_alg': enc_alg,
        'enc_nonce': enc_nonce,
        'enc_options': enc_options,
    }


def _pack_kdf_header(alg, salt, options):
    packed_options = alg.pack_options(options)

    return (KDF_HEADER_STRUCT.pack(alg.id, len(salt), len(packed_options))
            + salt
            + packed_options
            )


def _unpack_kdf_header(packed_header):
    alg_id, salt_size, options_size = KDF_HEADER_STRUCT.unpack(packed_header[0:KDF_HEADER_STRUCT.size])
    salt_start = KDF_HEADER_STRUCT.size
    options_start = salt_start + salt_size

    alg = kdf.by_id(alg_id)
    salt = packed_header[salt_start:salt_start + salt_size]
    options = alg.unpack_options(packed_header[options_start:options_start + options_size])

    return alg, salt, options


def _pack_enc_header(alg, nonce, options):
    packed_options = alg.pack_options(options)

    return (ENC_HEADER_STRUCT.pack(alg.id, len(nonce), len(packed_options))
            + nonce
            + packed_options
            )


def _unpack_enc_header(packed_header):
    alg_id, nonce_size, options_size = ENC_HEADER_STRUCT.unpack(packed_header[0:ENC_HEADER_STRUCT.size])
    nonce_start = ENC_HEADER_STRUCT.size
    options_start = nonce_start + nonce_size

    alg = cipher.by_id(alg_id)
    nonce = packed_header[nonce_start:nonce_start + nonce_size]
    options = alg.unpack_options(packed_header[options_start:options_start + options_size])

    return alg, nonce, options
