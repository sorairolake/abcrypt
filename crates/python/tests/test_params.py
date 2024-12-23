# SPDX-FileCopyrightText: 2024 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

from pathlib import Path
from typing import Final

import abcrypt_py

TEST_DIR: Final[Path] = Path(__file__).resolve().parent
TEST_DATA_ENC: Final[bytes] = Path(
    TEST_DIR / "data/v1/argon2id/v0x13/data.txt.abcrypt"
).read_bytes()


def test_success() -> None:
    abcrypt_py.Params(TEST_DATA_ENC)


def test_memory_cost_from_argon2d_and_v0x10() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2d/v0x10/data.txt.abcrypt").read_bytes()
    )
    assert params.memory_cost == 47104


def test_memory_cost_from_argon2d_and_v0x13() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2d/v0x13/data.txt.abcrypt").read_bytes()
    )
    assert params.memory_cost == 19456


def test_memory_cost_from_argon2i_and_v0x10() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2i/v0x10/data.txt.abcrypt").read_bytes()
    )
    assert params.memory_cost == 12288


def test_memory_cost_from_argon2i_and_v0x13() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2i/v0x13/data.txt.abcrypt").read_bytes()
    )
    assert params.memory_cost == 9216


def test_memory_cost_from_argon2id_and_v0x10() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2id/v0x10/data.txt.abcrypt").read_bytes()
    )
    assert params.memory_cost == 7168


def test_memory_cost_from_argon2id_and_v0x13() -> None:
    params = abcrypt_py.Params(TEST_DATA_ENC)
    assert params.memory_cost == 32


def test_time_cost_from_argon2d_and_v0x10() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2d/v0x10/data.txt.abcrypt").read_bytes()
    )
    assert params.time_cost == 1


def test_time_cost_from_argon2d_and_v0x13() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2d/v0x13/data.txt.abcrypt").read_bytes()
    )
    assert params.time_cost == 2


def test_time_cost_from_argon2i_and_v0x10() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2i/v0x10/data.txt.abcrypt").read_bytes()
    )
    assert params.time_cost == 3


def test_time_cost_from_argon2i_and_v0x13() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2i/v0x13/data.txt.abcrypt").read_bytes()
    )
    assert params.time_cost == 4


def test_time_cost_from_argon2id_and_v0x10() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2id/v0x10/data.txt.abcrypt").read_bytes()
    )
    assert params.time_cost == 5


def test_time_cost_from_argon2id_and_v0x13() -> None:
    params = abcrypt_py.Params(TEST_DATA_ENC)
    assert params.time_cost == 3


def test_parallelism_from_argon2d_and_v0x10() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2d/v0x10/data.txt.abcrypt").read_bytes()
    )
    assert params.parallelism == 1


def test_parallelism_from_argon2d_and_v0x13() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2d/v0x13/data.txt.abcrypt").read_bytes()
    )
    assert params.parallelism == 1


def test_parallelism_from_argon2i_and_v0x10() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2i/v0x10/data.txt.abcrypt").read_bytes()
    )
    assert params.parallelism == 1


def test_parallelism_from_argon2i_and_v0x13() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2i/v0x13/data.txt.abcrypt").read_bytes()
    )
    assert params.parallelism == 1


def test_parallelism_from_argon2id_and_v0x10() -> None:
    params = abcrypt_py.Params(
        Path(TEST_DIR / "data/v1/argon2id/v0x10/data.txt.abcrypt").read_bytes()
    )
    assert params.parallelism == 1


def test_parallelism_from_argon2id_and_v0x13() -> None:
    params = abcrypt_py.Params(TEST_DATA_ENC)
    assert params.parallelism == 4
