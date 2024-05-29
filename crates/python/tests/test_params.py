# SPDX-FileCopyrightText: 2024 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

from pathlib import Path
from typing import Final

import abcrypt_py

TEST_DIR: Final[Path] = Path(__file__).resolve().parent
TEST_DATA_ENC: Final[bytes] = Path(
    TEST_DIR / "data/data.txt.abcrypt"
).read_bytes()


def test_success() -> None:
    abcrypt_py.Params(TEST_DATA_ENC)


def test_memory_cost() -> None:
    params = abcrypt_py.Params(TEST_DATA_ENC)
    assert params.memory_cost == 32


def test_time_cost() -> None:
    params = abcrypt_py.Params(TEST_DATA_ENC)
    assert params.time_cost == 3


def test_parallelism() -> None:
    params = abcrypt_py.Params(TEST_DATA_ENC)
    assert params.parallelism == 4
