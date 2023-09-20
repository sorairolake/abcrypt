// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <format>
#include <iostream>

constexpr auto VERSION = "0.1.0";

void print_version(void) {
  std::cout << std::format("abcrypt-capi {}", VERSION) << std::endl;
}
