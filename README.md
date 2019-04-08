# Password Strength Calculator

Password Strength Calculator is the script to determine the strength of your password.

It gives him a rating from 1 to 10: 1 - very weak, 10 - strong and recommended to use.

Criteria for evaluation:

* the use of both upper-case and lower-case letters (case sensitivity)
* inclusion of one or more numerical digits
* inclusion of special characters, such as @, #, $
* prohibition of words found in a password blacklist
* some characters at the beginning or end reduce the strength of the password

# Quickstart

To work, you need a list of weak passwords, you can take it at [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials).

Place the list file next to the script in the passwords.txt file or specify the path to it using the --weak-list parameter.

The script requires an installed Python interpreter version 3.5, no additional packages required.

Example of script launch on Linux, Python 3.5:

```bash

password_strength.py -v -p 7#$fewrD -f pass.txt
Password strength: ++++++++-- [8/10]

```

Use in Windows similarly.

# Project Goals

The code is written for educational purposes. Training course for web-developers - [DEVMAN.org](https://devman.org)
