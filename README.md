What is this?
=============

This is a utility for creating files storing arbitrary content encrypted with password. The intention is
to encrypt small files with sensitive credentials such as AWS access tokens. Though there is nothing specific
about the content, this can encrypt arbitrary binary content.

The purpose of this module is to:

* Generate a key suitable for AES from the password
* Generate the necessary Salts, Nonces and IVs
* Setup a modern AEAD encryption mode
* Pack the resulting ciphertext, tag and options into a single file

This is only suitable for relatively small encrypted content (less than 64K). This limit is because the file
format only allows 2 bytes for the length of the encrypted content. This limit may be removed in future if there
is a need.

Security Warning
----------------

This project was created because I couldn't find an equivalent, but I'd strongly recommend searching for
alternatives or performing a security review before using in any sensitive application. Best effort has been made
to use common implementations of cryptographic primitives in a best practice way. But there has been no independent
review.

Any feedback on potential or actual security issues would be highly appreciated.

See the [Encryption](#encryption) section for details on the algorithms and settings used in the current implementation.

Of particular note, the default settings are not suitable if long term security of the encrypted data is required.
The KDF default settings have been picked so that decryption is relatively fast (~500ms) as that matches the intended 
se of secure storage of credentials that are rotated regularly. This setting does not provide sufficient protection
against brute forcing of the password to provide safe long term security.

Usage and Examples
==================

To encrypt some sensitive data call the `ocoen.filesecrets.encrypt` method with the data and a password. This returns
a `bytes` of the encrypted data, tag and options that can be written to a file. E.g.

    from ocoen import filesecrets

    data = 'my super secret credentials'.encode('UTF-8')
    encrypted_data = filesecrets.encrypt(data, 'my password')

    with open('encrypted_file', 'wb') as f:
        f.write(encrypted_data)

Similarly, to decrypt previously encrypted data, use the `ocoen.filesecrets.decrypt` method with the encrypted data
and the password.

    from ocoen import filesecrets

    with open('encrypted_file', 'rb') as f:
        encrypted_data = f.readall()

    data = filesecrets.decrypt(data, 'my password')

Note that that both the raw data and the encrypted package are binary data so are expected / returned as `bytes`.
If you want to encrypt string data you must covert it to bytes using `encode` as in the example above.

Both the `encrypt` and `decrypt` methods can also be passed additional data that is included in the integrity check
but not encrypted. This can be used to tie the encrypted payload to it's expected use (e.g. include the file name
in the integrity check). Additional data is passed as a third parameter:

    data = 'my super secret credentials'.encode('UTF-8')
    additional_data = 'thefilename'.encode('UTF-8')

    # encrypt including additional data in the integrity check
    encrypted_data = filesecrets.encrypt(data, 'my password', additional_data)

    # decrypt requires the same additional data to pass the integrity check
    unencrypted_data = filesecrets.encrypt(data, 'my password', additional_data)

    # Fails the integrity check since the additional data is not provided
    filesecrets.encrypt(data, 'my password')

As with the data, the additional data is binary so strings must be encoded before being passed to `encrypt` or `decrypt`.

The `ocoen.filesecrets.is_encrypted` method can be used to determine if a given `bytes` is an encrypted package. E.g,:

    data = ...
    if ocoen.filesecrets.is_encrypted(data):
        password = getpass.getpass()
        data = ocoen.filesecrets.decrypt(data)

Changing KDF and Encryption Options
-----------------------------------

It's possible to specify different options for the KDF and encryption algorithms by creating your own
`ocoen.filesecrets.Encrypter` rather than just using the encrypt method. E.g.

    from ocoen.filesecrets import Encrypter, cipher, kdf

    data = 'my super secret credentials'.encode('UTF-8')

    encrypter = Encrypter(
                          kdf_alg=kdf.scrypt
                          kdf_options={
                              'N': 131072,
                              'r': 8,
                              'p': 1,
                          },
                          enc_alg=cipher.AES256_SIV,
                          enc_options={}
                         )
    encrypted_data = encrypter.encrypt(data, 'my password')

It's also theoretically possible to specify a different KDF algorithm or different encryption algorithm / mode.
Theoretically because currently there is exactly 1 of each defined. New algorithms would have to be added to
[ocoen.filesecrets.kdf](src/ocoen/filesecrets/kdf.py) and [ocoen.filesecrets.cipher](src/ocoen/filesecrets/cipher.py)
respectively.

Note: There is no equivalent `Decrypter` class. The `decrypt` method reads all it's options from the encrypted package, so
payloads encrypted with customized settings are decrypted using the `decrypt` method as in the earlier examples.

Command Line Usage
------------------

The module also include a command line utility for encrypting and decrypting file content.

To encrypt use the `fs-encrypt` command:

    $ fs-encrypt inputfile outputfile

Either argument can be `-` to indicate that stdin / stdout should be used. Output file is optional and defaults
to stdout.

To decrypt use the `fs-decrypt` command:

    $ fs-decrypt inputfile outputfile

Again, either argument can be `-` to indicate that stdin / stdout should be used. Output file is optional and defaults
to stdout.


The `fs-rekey` command can be used to re-encrypt an encrypted file with a new password:

    $ fs-rekey file

Unlike the other two commands, this cannot use stdin / stdout as that doesn't make much sense.

Design and Implementation Details
=================================

Encrypted Data Format
---------------------

`ocoen.filesecrets.encrypt` creates a binary package containing the encrypted ciphertext, the AEAD tag and all the
details of the algorithms and options used for encryption. While currently only AES256 SIV mode with scrypt KDF is
supported the idea is to ensure the package contains all the settings needed to decrypt the data to allow for
future support of different algorithms.

The binary format is designed to allow future extension while supporting both forward and backward compatibility,
This is almost certainly overkill, but gotta keep it interesting.

The format consist of 5 segments:

* **File Format Version** a 4 byte magic number indicating which version of the format the package was create with
  This is used both to identify the format version, but also as a magic number to allow encrypted packages to
  be idetified.
* **Package Index** contains information on where in the package the other segments are.
* **Encryption Info** contains the algorithms, modes, salts etc that the data was encrypted with,
* **Ciphertext** the actual encrypted data.
* **Tag** the AEAD authentication tag used to validate the encrypted data has not been tampered with.

The package index segment describes the location of all of the other segments. As a result the start of the package
currently looks like:

       0      1      2      3      4      5      6      7      8
    +------+------+------+------+------+------+------+------+------+---
    | 0xf4 | 0x5f | 0xff | 0x73 | PISZ | EISZ |     CTSZ    | TGSZ |
    +------+------+------+------+------+------+------+------+------+---

      Byte |
    +------+------+-------------------------------------------------------------------------------------------------+
    | 0-3  |      | File Format Version: Magic number 0xf45fff73 indication the file format
    +------+------+-------------------------------------------------------------------------------------------------+
    |      |      | Package Index Size: The number of bytes used for the package index (including this one).        |
    |  4   | PISZ | Curretly always 5. This is recorded so that we can maintain forwards compatability in future by |
    |      |      | ignoring any additional index fields before the start of the encryption info.                   |
    +------+------+-------------------------------------------------------------------------------------------------+
    |  5   | EISZ | Encryption Info Size: The number of bytes after the packaage index that are used to describe    |
    |      |      | the algorithms and parameters in use to encrypt the payload.                                    |
    +------+------+-------------------------------------------------------------------------------------------------+
    | 6-7  | CTSZ | Cipertext Size: The number of bytes after the ecryption info that are used to store the         |
    |      |      | cipertext. Like all multi-byte fields this is stored big endien.                                |
    +------+------+-------------------------------------------------------------------------------------------------+
    |  8   | TGSZ | Tag Size: The  number of bytes after the ciphertext used to store the AEAD tag.                 |
    +------+------+-------------------------------------------------------------------------------------------------+

### Encryption Info Format

The encryption info records what algorithms and parameters were used to encrypt the data. This is structured into 3
segments:

* **Encryption Info Index** describes the size / location of the various segments within the encryption info.
* **KDF Settings** describes the details of the key derivation algorithm used to process the password into a key.
* **Encryption Settings** describes the details of the encryption algorithm used to encrypt the data.

The index segment describes the location of all of the other segments. As a result the start of the encryption info
currently looks like:

       0      1      2
    +------+------+------+---
    | IxSZ | KDFS | ENCS |
    +------+------+------+---

      Byte |
    +------+------+-------------------------------------------------------------------------------------------------+
    |      |      | Index Size: The number of bytes used for the encryption info index (including this one).        |
    |  0   | IxSZ | Curretly always 3. This is recorded so that we can maintain forwards compatability in future by |
    |      |      | ignoring any additional index fields before the start of the KDF settings.                      |
    +------+------+-------------------------------------------------------------------------------------------------+
    |  1   | KDFS | KDF Settigs Size: The number of bytes after the index segment used to desribe the KDF settings. |
    +------+------+-------------------------------------------------------------------------------------------------+
    |  2   | ENCS | Encryption Settings Size: The number of bytes after the KDF settings segment used to desribe    |
    |      |      | the encryption algorithm and settings used to encrypt the data.                                 |
    +------+------+-------------------------------------------------------------------------------------------------+

#### KDF Settings Format

The KDF Settings consists of three parts:

* **KDF Settings Header** Indicates what KDF algorithm is in use as well as the sizes of the remaining parts.
* **Salt** The salt used for the KDF algorithm.
* **KDF Options** The algorithm specific options that configure the KDF.

The header describes the location of all of the other parts, the algorithm implied also indicates the structure of
the options part. The start of the KDF Settings looks like:

       0      1      2
    +------+------+------+---
    | ALG  | STSZ | OPSZ |
    +------+------+------+---

      Byte |
    +------+------+-------------------------------------------------------------------------------------------------+
    |  0   | ALG  | Algorithm: indicates which KDF algorithm was used to derive the key (see table below).          |
    +------+------+-------------------------------------------------------------------------------------------------+
    |  1   | STSZ | Salt Size: The number of bytes after the header used to store the KDF salt.                     |
    +------+------+-------------------------------------------------------------------------------------------------+
    |  2   | OPSZ | Options Size: The number of bytes after the salt used to store the algorithm specific options.  |
    +------+------+-------------------------------------------------------------------------------------------------+

##### KDF Algorithms

    | Id | Algorithm | Options Format                        |
    +----+-----------+---------------------------------------+
    |    |           | Byte 0-3: N Value (stored big-endian) |
    | 1  |  scrypt   | Byte 1:   r Value                     |
    |    |           | Byte 0:   p Value                     |
    +----+-----------+---------------------------------------+

#### Encryption Settings Format

The Encryption Settings consists of a header indicating what algorithm and mode were used as well as the size of the
two otheer parts, the IV/Nonce data and the algorithm / mode specific options part. The start of the encryption settings
looks like:

       0      1      2
    +------+------+------+---
    | ALG  | IVSZ | OPSZ |
    +------+------+------+---

      Byte |
    +------+------+-------------------------------------------------------------------------------------------------+
    |  0   | ALG  | Algorithm: indicates which encryption algorithm and mode was used to encrypt the data. see table|
    +------+------+-------------------------------------------------------------------------------------------------+
    |  1   | IVSZ | IV / Nonce Size: The number of bytes after the header used to store the IV or Nonce.            |
    +------+------+-------------------------------------------------------------------------------------------------+
    |  2   | OPSZ | Options Size: The number of bytes after the IV used to store the algorithm specific options.    |
    +------+------+-------------------------------------------------------------------------------------------------+

##### Encryption Algorithms and Modes

    | Id | Algorithm | Mode | Options Format  |
    +----+-----------+------+-----------------+
    | 1  |   AES256  | SIV  | None            |
    +----+-----------+------+-----------------+

Encryption
----------

This section describes the various algorithms and options used in securing the data payload and the rationale for these
choices.

All security relevant algorithms (Encryption, KDF, PRNG) use implementations from [PyCryptodome](https://www.pycryptodome.org/en/latest/index.html)
which appears to be the defacto standard implementation for Python.

**Key Derivation**

Key derivation is done using `scrypt` with the following options:

* _salt_ - 16 random bytes
* _N_ - 131072
* _r_ - 8
* _p_ - 1
* _generated key length_ - 64 bytes

Scrypt was chosen because I believe it's considered the current best practice for KDF as it's GPU resistant unlike other
common KDF algorithms.

The parameters (N particularly) was chosen so that derivation takes ~500ms. This is generally considered too low for
long term storage that might be subject to offline attack. However as this is intended for credential storage the decryption
will happen more often than standard applications like disk encryption. So on balance the shorter time is necessary for
usability. Credentials must still be rotated as expected.

The key length is chosen because it's what's required for AES256 with the SIV mode.

**Encryption**

Encryption is done using AES256 in SIV mode using a 16 byte random nonce. SIV was selected because unlike other AEAD modes
it's resistant to IV / Nonce misuse. As this is intended for use without a central service there's no way to coordinate to
avoid IV reuse. Random IVs are unlikely to conflict, but paranoia never did any harm with cryptography.
