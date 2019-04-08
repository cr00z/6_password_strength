import re
import os
import argparse


def check_password_length(password):
    pw_len_strength = (len(password) - 4) * 2
    if pw_len_strength < 4:
        pw_len_strength = 1
    if pw_len_strength > 10:
        pw_len_strength = 10
    return pw_len_strength


def check_password_symbols(password):
    pw_symb_strength = 0
    if not re.search(r'[a-z]', password):
        pw_symb_strength -= 2
    if not re.search(r'[A-Z]', password):
        pw_symb_strength -= 2
    if not re.search(r'\d', password):
        pw_symb_strength -= 2
    if not re.search(r'\W', password):
        pw_symb_strength -= 2
    return pw_symb_strength


def check_password_weak_list(password, pw_file_path):
    pw_lower = password.lower()
    pw_is_weak = False
    with open(pw_file_path) as passw_file:
        for weak_pass in passw_file.readlines():
            if weak_pass.lower().strip() == pw_lower:
                pw_is_weak = True
                break
    return pw_is_weak


def check_password_mask(password):
    pw_symb_strenght = 0
    if re.fullmatch(r'^[A-Z][^A-Z]*]', password):   # e.g. Xaaaaaaa
        pw_symb_strenght -= 1
    if re.fullmatch(r'\D*..\d\d$', password):       # e.g. aaaaaa11 or aaaa1981
        pw_symb_strenght -= 1
    if re.fullmatch(r'^[A-Za-z]\W\W]', password):   # e.g. aaaaaa1! or aaaaaa@2
        pw_symb_strenght -= 1
    return pw_symb_strenght


def get_password_strength(password, pw_file_path):
    pw_strength = check_password_length(password) + \
                  check_password_symbols(password) +\
                  check_password_mask(password)
    pw_is_weak = check_password_weak_list(password, pw_file_path)
    if pw_strength < 1 or pw_is_weak:
        pw_strength = 1
    return pw_strength


def get_cmdline_args():
    parser = argparse.ArgumentParser(
        description='Script to determine the strength of your password')
    parser.add_argument('-f', '--weak_list', action='store',
                        default='passwords.txt', type=str,
                        help='path to list of weak passwords')
    parser.add_argument('-p', '--test_pass', action='store', default='',
                        type=str, help='your password')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='increase output verbosity')
    return parser.parse_args()


if __name__ == '__main__':
    args = get_cmdline_args()
    if not os.path.exists(args.weak_list):
        exit('Weak password list file not found')
    if args.test_pass == '':
        tested_password = input("Input your password: ")
    else:
        tested_password = args.test_pass
    password_strength = get_password_strength(tested_password, args.weak_list)
    if args.verbose:
        print("Password strength: {}{} [{}/10]".format('+' * password_strength,
                                                       '-' * (10-password_strength),
                                                       password_strength))
    else:
        print(password_strength)
