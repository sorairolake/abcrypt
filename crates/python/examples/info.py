#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2024 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

import argparse
import sys

import abcrypt_py


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="info",
        description="An example of reading the Argon2 parameters from a file",
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

    params = abcrypt_py.Params(ciphertext)
    print(
        f"Parameters used: memoryCost = {params.memory_cost}; timeCost = {params.time_cost}; parallelism = {params.parallelism};"
    )


if __name__ == "__main__":
    main()
