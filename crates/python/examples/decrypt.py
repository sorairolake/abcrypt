#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2024 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

import argparse
import getpass
import sys

import abcrypt_py
import version


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="decrypt",
        description="An example of decrypting a file from the abcrypt encrypted data format",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=version.VERSION
    )
    parser.add_argument(
        "-o",
        "--output",
        default=sys.stdout.buffer,
        type=argparse.FileType("wb"),
        help="output the result to a file",
        metavar="FILE",
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=sys.stdin,
        type=argparse.FileType("rb"),
        help="input file",
        metavar="FILE",
    )
    args = parser.parse_args()

    ciphertext = args.input.read()

    passphrase = bytes(getpass.getpass("Enter passphrase: "), encoding="utf-8")
    plaintext = abcrypt_py.decrypt(ciphertext, passphrase)

    args.output.write(plaintext)


if __name__ == "__main__":
    main()
