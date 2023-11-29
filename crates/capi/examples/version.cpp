// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <fmt/core.h>

#include <iostream>

constexpr auto VERSION = "0.2.2";

void print_version(void) {
  std::cout << fmt::format("abcrypt-capi {}", VERSION) << std::endl;
}
