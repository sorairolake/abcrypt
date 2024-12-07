# SPDX-FileCopyrightText: 2024 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

from typing import Final

def encrypt(plaintext: bytes, passphrase: bytes) -> bytes: ...
def encrypt_with_params(
    plaintext: bytes,
    passphrase: bytes,
    memory_cost: int,
    time_cost: int,
    parallelism: int,
) -> bytes: ...
def encrypt_with_type(
    plaintext: bytes,
    passphrase: bytes,
    argon2_type: int,
    memory_cost: int,
    time_cost: int,
    parallelism: int,
) -> bytes: ...
def encrypt_with_version(
    plaintext: bytes,
    passphrase: bytes,
    argon2_type: int,
    argon2_version: int,
    memory_cost: int,
    time_cost: int,
    parallelism: int,
) -> bytes: ...
def decrypt(ciphertext: bytes, passphrase: bytes) -> bytes: ...

class Params:
    def __init__(self, ciphertext: bytes) -> None: ...
    @property
    def memory_cost(self) -> int: ...
    @property
    def time_cost(self) -> int: ...
    @property
    def parallelism(self) -> int: ...

class Format:
    HEADER_SIZE: Final[int]
    TAG_SIZE: Final[int]
