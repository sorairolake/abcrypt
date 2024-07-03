# SPDX-FileCopyrightText: 2024 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

from pathlib import Path
from typing import Final

import abcrypt_py

PASSPHRASE: Final[bytes] = b"passphrase"
TEST_DIR: Final[Path] = Path(__file__).resolve().parent
TEST_DATA: Final[bytes] = Path(TEST_DIR / "data/data.txt").read_bytes()


def test_success() -> None:
    ciphertext = abcrypt_py.encrypt(TEST_DATA, PASSPHRASE)
    assert ciphertext != TEST_DATA
    assert (
        len(ciphertext)
        == len(TEST_DATA)
        + abcrypt_py.Format.HEADER_SIZE
        + abcrypt_py.Format.TAG_SIZE
    )

    params = abcrypt_py.Params(ciphertext)
    assert params.memory_cost == 19456
    assert params.time_cost == 2
    assert params.parallelism == 1

    plaintext = abcrypt_py.decrypt(ciphertext, PASSPHRASE)
    assert plaintext == TEST_DATA


def test_success_with_params() -> None:
    ciphertext = abcrypt_py.encrypt_with_params(
        TEST_DATA, PASSPHRASE, 32, 3, 4
    )
    assert ciphertext != TEST_DATA
    assert (
        len(ciphertext)
        == len(TEST_DATA)
        + abcrypt_py.Format.HEADER_SIZE
        + abcrypt_py.Format.TAG_SIZE
    )

    params = abcrypt_py.Params(ciphertext)
    assert params.memory_cost == 32
    assert params.time_cost == 3
    assert params.parallelism == 4

    plaintext = abcrypt_py.decrypt(ciphertext, PASSPHRASE)
    assert plaintext == TEST_DATA


def test_minimum_output_length() -> None:
    ciphertext = abcrypt_py.encrypt_with_params(b"", PASSPHRASE, 32, 3, 4)
    assert (
        len(ciphertext)
        == abcrypt_py.Format.HEADER_SIZE + abcrypt_py.Format.TAG_SIZE
    )


def test_magic_number() -> None:
    ciphertext = abcrypt_py.encrypt_with_params(
        TEST_DATA, PASSPHRASE, 32, 3, 4
    )
    assert ciphertext[:7] == b"abcrypt"


def test_version() -> None:
    ciphertext = abcrypt_py.encrypt_with_params(
        TEST_DATA, PASSPHRASE, 32, 3, 4
    )
    assert ciphertext[7] == 0


def test_memory_cost() -> None:
    ciphertext = abcrypt_py.encrypt_with_params(
        TEST_DATA, PASSPHRASE, 32, 3, 4
    )
    assert ciphertext[8:12] == (32).to_bytes(4, byteorder="little")


def test_time_cost() -> None:
    ciphertext = abcrypt_py.encrypt_with_params(
        TEST_DATA, PASSPHRASE, 32, 3, 4
    )
    assert ciphertext[12:16] == (3).to_bytes(4, byteorder="little")


def test_parallelism() -> None:
    ciphertext = abcrypt_py.encrypt_with_params(
        TEST_DATA, PASSPHRASE, 32, 3, 4
    )
    assert ciphertext[16:20] == (4).to_bytes(4, byteorder="little")
