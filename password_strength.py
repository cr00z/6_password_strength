import re
import os
import argparse
import getpass


MIN_PW_STRENGTH = 1
MAX_PW_STRENGTH = 10
MIN_PW_LEN = 6
MIN_PW_LEN_STRENGTH = 4
NO_SYMBOL_CORRECTION = 2
BAD_MASK_CORRECTION = 1


def get_password_len_strength(password):
    if len(password) < MIN_PW_LEN:
        pw_len_strength = MIN_PW_STRENGTH
    else:
        pw_len_strength = MIN_PW_LEN_STRENGTH + (len(password) - MIN_PW_LEN) * 2
        if pw_len_strength > MAX_PW_STRENGTH:
            pw_len_strength = MAX_PW_STRENGTH
    return pw_len_strength


def get_password_symbols_correction(password):
    pw_symb_correction = 0
    if not re.search(r'[a-z]', password):
        pw_symb_correction -= NO_SYMBOL_CORRECTION
    if not re.search(r'[A-Z]', password):
        pw_symb_correction -= NO_SYMBOL_CORRECTION
    if not re.search(r'\d', password):
        pw_symb_correction -= NO_SYMBOL_CORRECTION
    if not re.search(r'\W', password):
        pw_symb_correction -= NO_SYMBOL_CORRECTION
    return pw_symb_correction


def get_password_mask_correction(password):
    pw_mask_correction = 0
    if re.fullmatch(r'^[A-Z][^A-Z]*]', password):   # e.g. Xaaaaaaa
        pw_mask_correction -= BAD_MASK_CORRECTION
    if re.fullmatch(r'\D*..\d\d$', password):       # e.g. aaaaaa11 or aaaa1981
        pw_mask_correction -= BAD_MASK_CORRECTION
    if re.fullmatch(r'^[A-Za-z]\W\W]', password):   # e.g. aaaaaa1! or aaaaaa@2
        pw_mask_correction -= BAD_MASK_CORRECTION
    return pw_mask_correction


def load_weak_passwords_list(pw_file_path):
    if not os.path.exists(pw_file_path):
        return None
    with open(pw_file_path) as passw_file:
        return map(lambda pw: pw.lower(), passw_file.read().splitlines())


def check_password_in_weak_list(password, weak_passwords_list):
    return password.lower() in weak_passwords_list


def get_password_strength(password, weak_password_list):
    pw_strength_components = [
        get_password_len_strength(password),
        get_password_symbols_correction(password),
        get_password_mask_correction(password)
    ]
    pw_strength = sum(pw_strength_components)
    pw_is_weak = False
    if weak_passwords_list is not None:
        pw_is_weak = check_password_in_weak_list(password, weak_password_list)
    if pw_strength < MIN_PW_STRENGTH or pw_is_weak:
        pw_strength = MIN_PW_STRENGTH
    return pw_strength


def get_cmdline_args():
    parser = argparse.ArgumentParser(
        description='Script to determine the strength of your password'
    )
    parser.add_argument(
        '-f',
        '--weak_list',
        default='passwords.txt',
        help='path to list of weak passwords'
    )
    parser.add_argument(
        '-p',
        '--test_pass',
        default='',
        help='your password'
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='increase output verbosity'
    )
    return parser.parse_args()


if __name__ == '__main__':
    args = get_cmdline_args()
    weak_passwords_list = load_weak_passwords_list(args.weak_list)
    if weak_passwords_list is None:
        print('Weak password list file not found, weak list test not supported')
    if args.test_pass == '':
        tested_password = getpass.getpass("Input your password: ")
    else:
        tested_password = args.test_pass
    password_strength = get_password_strength(tested_password, weak_passwords_list)
    if args.verbose:
        print("Password strength: {}{} [{}/10]".format(
            '+' * password_strength,
            '-' * (10-password_strength),
            password_strength)
        )
    else:
        print(password_strength)
