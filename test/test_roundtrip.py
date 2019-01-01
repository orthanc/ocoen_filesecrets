from ocoen.filesecrets import encrypt, decrypt

data = 'hello world'.encode('UTF-8')
additional_data = 'cruel'.encode('UTF-8')
password = 'password'


def test_roundtrip():
    encrypted_data = encrypt(data, password)
    unencrypted_data = decrypt(encrypted_data, password)

    assert unencrypted_data == data


def test_roundtrip_with_additional_data():
    encrypted_data = encrypt(data, password, additional_data)
    unencrypted_data = decrypt(encrypted_data, password, additional_data)

    assert unencrypted_data == data
