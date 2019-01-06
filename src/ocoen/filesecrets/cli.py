import sys
from contextlib import contextmanager
from argparse import ArgumentParser
from getpass import getpass

from ocoen import filesecrets

common_options = ArgumentParser(add_help=False)
common_options.add_argument('--additional-data', '-d',
                            help='The additional data to include in the hash. Will be UTF-8 encoded. '
                                 + 'If starts with an \'@\' will be treated as a file path.')
password_group = common_options.add_mutually_exclusive_group()
password_group.add_argument('--password',
                            help='The password to use. If neither this or --password-file are specified '
                                 + 'the user will be prompted for a password.')
password_group.add_argument('--password-file',
                            help='The file containing the password to use. - to read from stdin If neither '
                                 + 'this or --password are specified the user will be prompted for a password.')

file_options = ArgumentParser(add_help=False)
file_options.add_argument('infile',
                          help='The file to read from. - means read from stdin.')
file_options.add_argument('outfile', nargs='?', default='-',
                          help='The file to write to. - (the default) means write to stdout.')


def _get_password(args, prompt_prefix='', prefix='', confirm=False):
    args_dict = vars(args)

    password = args_dict[prefix + 'password']
    if password:
        return password
    password_file = args_dict[prefix + 'password_file']
    if password_file:
        with file_or_std(password_file, 'rb', sys.stdin) as f:
            return f.read()
    password = getpass(prompt_prefix + 'Password:')
    if confirm:
        password2 = getpass(prompt='Confirm ' + prompt_prefix + 'Password:')
        if password != password2:
            raise RuntimeError('Passwords do not match!')
    return password


def encrypt():
    parser = ArgumentParser(parents=[common_options, file_options])
    args = parser.parse_args()
    password = _get_password(args, confirm=True)
    additional_data = _load_additional_data(args.additional_data)

    with file_or_std(args.infile, 'rb', sys.stdin) as instream:
        encrypted_data = filesecrets.encrypt(instream.read(), password, additional_data)
    with file_or_std(args.outfile, 'wb', sys.stdout) as outstream:
        outstream.write(encrypted_data)
    return 0


def decrypt():
    parser = ArgumentParser(parents=[common_options, file_options])
    args = parser.parse_args()
    password = _get_password(args)
    additional_data = _load_additional_data(args.additional_data)

    with file_or_std(args.infile, 'rb', sys.stdin) as instream:
        data = filesecrets.decrypt(instream.read(), password, additional_data)
    with file_or_std(args.outfile, 'wb', sys.stdout) as outstream:
        outstream.write(data)
    return 0


def rekey():
    parser = ArgumentParser(parents=[common_options])
    new_pass_group = parser.add_mutually_exclusive_group()
    new_pass_group.add_argument('--new-password',
                                help='The new password to use. If neither this or --new-password-file are specified '
                                     + 'the user will be prompted for a password.')
    new_pass_group.add_argument('--new-password-file',
                                help='The file containing the new password to use. - to read from stdin. If neither '
                                     + 'this or --new-password are specified the user will be prompted for a password.')
    parser.add_argument('file', help='The file to rekey.')
    args = parser.parse_args()
    password = _get_password(args, prompt_prefix='Current ')
    new_password = _get_password(args, prompt_prefix='New ', prefix='new_', confirm=True)
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


@contextmanager
def file_or_std(filearg, mode, stream):
    if filearg == '-':
        if 'b' in mode:
            yield stream.buffer
        else:
            yield stream
    else:
        with open(filearg, mode) as f:
            yield f
