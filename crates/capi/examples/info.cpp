// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// An example of reading the Argon2 parameters from a file.

#include <fmt/core.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "abcrypt.h"
#include "version.hpp"

static void print_help(void) {
  std::cout << "Usage: info <FILE>\n\n";
  std::cout << "Arguments:\n";
  std::cout << "  <FILE>  File to print the Argon2 parameters\n\n";
  std::cout << "Options:\n";
  std::cout << "  -h  Print help\n";
  std::cout << "  -V  Print version" << std::endl;
}

int main(int argc, char *argv[]) {
  int opt;
  while ((opt = getopt(argc, argv, "hV")) != -1) {
    switch (opt) {
      case 'h':
        print_help();
        return EXIT_SUCCESS;
      case 'V':
        print_version();
        return EXIT_SUCCESS;
      default:
        print_help();
        return EXIT_FAILURE;
    }
  }

  char *input_filename;
  if ((argc - optind) == 1) {
    input_filename = argv[optind];
  } else {
    print_help();
    return EXIT_FAILURE;
  }

  std::ifstream input_file(input_filename);
  if (!input_file) {
    std::clog << fmt::format("Error: could not open {}: {}", input_filename,
                             std::strerror(errno))
              << std::endl;
    return EXIT_FAILURE;
  }
  std::vector<std::uint8_t> contents{
      (std::istreambuf_iterator<char>(input_file)),
      std::istreambuf_iterator<char>()};

  auto params = abcrypt_params_new();
  auto error_code =
      abcrypt_params_read(contents.data(), contents.size(), params);
  if (error_code != ABCRYPT_ERROR_CODE_OK) {
    std::vector<std::uint8_t> buf(abcrypt_error_message_out_len(error_code));
    abcrypt_error_message(error_code, buf.data(), buf.size());
    std::string error_message(std::cbegin(buf), std::cend(buf));
    std::clog << fmt::format(
                     "Error: {} is not a valid Argon2 encrypted file: {}",
                     input_filename, error_message)
              << std::endl;
    abcrypt_params_free(params);
    return EXIT_FAILURE;
  }
  auto m_cost = abcrypt_params_m_cost(params);
  auto t_cost = abcrypt_params_t_cost(params);
  auto p_cost = abcrypt_params_p_cost(params);
  abcrypt_params_free(params);

  std::cout << fmt::format("Parameters used: m = {}; t = {}; p = {};", m_cost,
                           t_cost, p_cost)
            << std::endl;
}
