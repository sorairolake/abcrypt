# SPDX-FileCopyrightText: 2024 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

from pathlib import Path
from typing import Final

import abcrypt_py
import pytest

PASSPHRASE: Final[bytes] = b"passphrase"
TEST_DIR: Final[Path] = Path(__file__).resolve().parent
TEST_DATA: Final[bytes] = Path(TEST_DIR / "data/data.txt").read_bytes()
TEST_DATA_ENC: Final[bytes] = Path(
    TEST_DIR / "data/v1/data.txt.abcrypt"
).read_bytes()


def test_success() -> None:
    plaintext = abcrypt_py.decrypt(TEST_DATA_ENC, PASSPHRASE)
    assert plaintext == TEST_DATA


def test_incorrect_passphrase() -> None:
    with pytest.raises(ValueError) as e:
        abcrypt_py.decrypt(TEST_DATA_ENC, b"password")
    assert str(e.value) == "invalid header MAC"


def test_invalid_input_length_1() -> None:
    data = bytes(
        (abcrypt_py.Format.HEADER_SIZE + abcrypt_py.Format.TAG_SIZE) - 1
    )
    with pytest.raises(ValueError) as e:
        abcrypt_py.decrypt(data, PASSPHRASE)
    assert str(e.value) == "encrypted data is shorter than 164 bytes"


def test_invalid_input_length_2() -> None:
    data = bytes(abcrypt_py.Format.HEADER_SIZE + abcrypt_py.Format.TAG_SIZE)
    with pytest.raises(ValueError) as e:
        abcrypt_py.decrypt(data, PASSPHRASE)
    assert str(e.value) == "invalid magic number"


def test_invalid_magic_number() -> None:
    data = bytearray(TEST_DATA_ENC)
    data[0] = int.from_bytes(b"b", byteorder="little")
    with pytest.raises(ValueError) as e:
        abcrypt_py.decrypt(bytes(data), PASSPHRASE)
    assert str(e.value) == "invalid magic number"


def test_unsupported_version() -> None:
    data = Path(TEST_DIR / "data/v0/data.txt.abcrypt").read_bytes()
    with pytest.raises(ValueError) as e:
        abcrypt_py.decrypt(data, PASSPHRASE)
    assert str(e.value) == "unsupported version number `0`"


def test_unknown_version() -> None:
    data = bytearray(TEST_DATA_ENC)
    data[7] = 2
    with pytest.raises(ValueError) as e:
        abcrypt_py.decrypt(bytes(data), PASSPHRASE)
    assert str(e.value) == "unknown version number `2`"


def test_invalid_memory_cost() -> None:
    data = bytearray(TEST_DATA_ENC)
    data[16:20] = (7).to_bytes(4, byteorder="little")
    with pytest.raises(ValueError) as e:
        abcrypt_py.decrypt(bytes(data), PASSPHRASE)
    assert str(e.value) == "invalid Argon2 parameters"


def test_invalid_time_cost() -> None:
    data = bytearray(TEST_DATA_ENC)
    data[20:24] = (0).to_bytes(4, byteorder="little")
    with pytest.raises(ValueError) as e:
        abcrypt_py.decrypt(bytes(data), PASSPHRASE)
    assert str(e.value) == "invalid Argon2 parameters"


def test_invalid_parallelism() -> None:
    data = bytearray(TEST_DATA_ENC)
    data[24:28] = (2**24).to_bytes(4, byteorder="little")
    with pytest.raises(ValueError) as e:
        abcrypt_py.decrypt(bytes(data), PASSPHRASE)
    assert str(e.value) == "invalid Argon2 parameters"


def test_invalid_header_mac() -> None:
    data = bytearray(TEST_DATA_ENC)
    header_mac = data[84:148]
    header_mac.reverse()
    data[84:148] = header_mac
    with pytest.raises(ValueError) as e:
        abcrypt_py.decrypt(bytes(data), PASSPHRASE)
    assert str(e.value) == "invalid header MAC"


def test_invalid_mac() -> None:
    data = bytearray(TEST_DATA_ENC)
    start_mac = len(data) - abcrypt_py.Format.TAG_SIZE
    mac = data[start_mac:]
    mac.reverse()
    data[start_mac:] = mac
    with pytest.raises(ValueError) as e:
        abcrypt_py.decrypt(bytes(data), PASSPHRASE)
    assert str(e.value) == "invalid ciphertext MAC"
