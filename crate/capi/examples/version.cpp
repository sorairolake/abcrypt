// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <iostream>

#include <fmt/core.h>

constexpr auto VERSION = "0.1.0";

void print_version(void) {
  std::cout << fmt::format("abcrypt-capi {}", VERSION) << std::endl;
}
