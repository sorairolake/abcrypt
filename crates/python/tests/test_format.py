# SPDX-FileCopyrightText: 2024 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

import abcrypt_py


def test_header_size() -> None:
    assert abcrypt_py.Format.HEADER_SIZE == 140


def test_tag_size() -> None:
    assert abcrypt_py.Format.TAG_SIZE == 16
