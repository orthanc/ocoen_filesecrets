import sys
from contextlib import contextmanager
from argparse import ArgumentParser
from getpass import getpass

from ocoen import filesecrets


def encrypt():
    parser = ArgumentParser()
    _add_file_args(parser)
    args = parser.parse_args()
    password = getpass()
    password2 = getpass(prompt='Confirm Password:')
    if password != password2:
        return 'Passwords do not match!'

    with file_or_std(args.infile, 'rb', sys.stdin) as instream:
        encrypted_data = filesecrets.encrypt(instream.read(), password)
    with file_or_std(args.outfile, 'wb', sys.stdout) as outstream:
        outstream.write(encrypted_data)
    return 0


def decrypt():
    parser = ArgumentParser()
    _add_file_args(parser)
    args = parser.parse_args()
    password = getpass()

    with file_or_std(args.infile, 'rb', sys.stdin) as instream:
        data = filesecrets.decrypt(instream.read(), password)
    with file_or_std(args.outfile, 'wb', sys.stdout) as outstream:
        outstream.write(data)
    return 0


def rekey():
    parser = ArgumentParser()
    parser.add_argument('file', help='The file to rekey.')
    args = parser.parse_args()
    password = getpass(prompt='Current Password:')
    new_password = getpass(prompt='New Password:')
    new_password2 = getpass(prompt='Confirm Password:')
    if new_password != new_password2:
        return 'Passwords do not match!'

    with open(args.file, 'rb') as instream:
        data = filesecrets.decrypt(instream.read(), password)
    with open(args.file, 'wb') as outstream:
        outstream.write(filesecrets.encrypt(data, new_password))
    return 0


def _add_file_args(parser):
    parser.add_argument('infile',
                        help='The file to read from. - means read from stdin.')
    parser.add_argument('outfile', nargs='?', default='-',
                        help='The file to write to. - (the default) means write to stdout.')


@contextmanager
def file_or_std(filearg, mode, stream):
    if filearg == '-':
        yield stream.buffer
    else:
        with open(filearg, mode) as f:
            yield f
