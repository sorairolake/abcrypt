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
        prog="encrypt",
        description="An example of encrypting a file to the abcrypt encrypted data format",
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
        "--argon2-type",
        default=2,
        type=int,
        choices=range(3),
        help="set the Argon2 type",
        metavar="TYPE",
    )
    parser.add_argument(
        "--argon2-version",
        default=0x13,
        type=int,
        choices=[0x10, 0x13],
        help="set the Argon2 version",
        metavar="VERSION",
    )
    parser.add_argument(
        "-m",
        "--memory-cost",
        default=19456,
        type=int,
        help="set the memory size in KiB",
        metavar="NUM",
    )
    parser.add_argument(
        "-t",
        "--time-cost",
        default=2,
        type=int,
        help="set the number of iterations",
        metavar="NUM",
    )
    parser.add_argument(
        "-p",
        "--parallelism",
        default=1,
        type=int,
        help="set the degree of parallelism",
        metavar="NUM",
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

    plaintext = args.input.read()

    passphrase = bytes(getpass.getpass("Enter passphrase: "), encoding="utf-8")
    ciphertext = abcrypt_py.encrypt_with_version(
        plaintext,
        passphrase,
        args.argon2_type,
        args.argon2_version,
        args.memory_cost,
        args.time_cost,
        args.parallelism,
    )

    args.output.write(ciphertext)


if __name__ == "__main__":
    main()
