import sys
from contextlib import contextmanager
from argparse import ArgumentParser
from getpass import getpass

from ocoen import filesecrets


def encrypt():
    parser = ArgumentParser()
    _add_file_args(parser)
    _add_additional_data_args(parser)
    args = parser.parse_args()
    password = getpass()
    password2 = getpass(prompt='Confirm Password:')
    if password != password2:
        return 'Passwords do not match!'
    additional_data = _load_additional_data(args.additional_data)

    with file_or_std(args.infile, 'rb', sys.stdin) as instream:
        encrypted_data = filesecrets.encrypt(instream.read(), password, additional_data)
    with file_or_std(args.outfile, 'wb', sys.stdout) as outstream:
        outstream.write(encrypted_data)
    return 0


def decrypt():
    parser = ArgumentParser()
    _add_file_args(parser)
    _add_additional_data_args(parser)
    args = parser.parse_args()
    password = getpass()
    additional_data = _load_additional_data(args.additional_data)

    with file_or_std(args.infile, 'rb', sys.stdin) as instream:
        data = filesecrets.decrypt(instream.read(), password, additional_data)
    with file_or_std(args.outfile, 'wb', sys.stdout) as outstream:
        outstream.write(data)
    return 0


def rekey():
    parser = ArgumentParser()
    parser.add_argument('file', help='The file to rekey.')
    _add_additional_data_args(parser)
    args = parser.parse_args()
    password = getpass(prompt='Current Password:')
    new_password = getpass(prompt='New Password:')
    new_password2 = getpass(prompt='Confirm Password:')
    if new_password != new_password2:
        return 'Passwords do not match!'
    additional_data = _load_additional_data(args.additional_data)

    with open(args.file, 'rb') as instream:
        data = filesecrets.decrypt(instream.read(), password, additional_data)
    with open(args.file, 'wb') as outstream:
        outstream.write(filesecrets.encrypt(data, new_password, additional_data))
    return 0


def _load_additional_data(additional_data_arg):
    if not additional_data_arg:
        return None
    elif additional_data_arg[0] == '@':
        with open(additional_data_arg[1:], 'rb') as f:
            return f.read()
    else:
        return additional_data_arg.encode('UTF-8')


def _add_file_args(parser):
    parser.add_argument('infile',
                        help='The file to read from. - means read from stdin.')
    parser.add_argument('outfile', nargs='?', default='-',
                        help='The file to write to. - (the default) means write to stdout.')


def _add_additional_data_args(parser):
    parser.add_argument('--additional-data', '-d',
                        help='The additional data to include in the hash. Will be UTF-8 encoded. '
                             + 'If starts with an \'@\' will be treated as a file path.')


@contextmanager
def file_or_std(filearg, mode, stream):
    if filearg == '-':
        yield stream.buffer
    else:
        with open(filearg, mode) as f:
            yield f
