// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// An example of reading the Argon2 parameters from a file.

#include <fmt/core.h>

#include <CLI/CLI.hpp>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include "abcrypt.h"
#include "version.hpp"

int main(int argc, char *argv[]) {
  CLI::App app{"An example of reading the Argon2 parameters"};
  app.set_version_flag("-V,--version", VERSION, "Print version");
  std::optional<std::string> input_filename;
  app.add_option("FILE", input_filename, "Input file");
  CLI11_PARSE(app, argc, argv);

  std::vector<std::uint8_t> contents;
  if (input_filename) {
    auto ifn = input_filename.value();
    std::ifstream input_file(ifn);
    if (!input_file) {
      std::clog << fmt::format("Error: could not open {}: {}", ifn,
                               std::strerror(errno))
                << std::endl;
      return EXIT_FAILURE;
    }
    contents = {(std::istreambuf_iterator<char>(input_file)),
                std::istreambuf_iterator<char>()};
  } else {
    contents = {(std::istreambuf_iterator<char>(std::cin)),
                std::istreambuf_iterator<char>()};
  }

  auto params = abcrypt_params_new();
  auto error_code =
      abcrypt_params_read(contents.data(), contents.size(), params);
  if (error_code != ABCRYPT_ERROR_CODE_OK) {
    std::vector<std::uint8_t> buf(abcrypt_error_message_out_len(error_code));
    abcrypt_error_message(error_code, buf.data(), buf.size());
    std::string error_message(buf.cbegin(), buf.cend());
    std::clog << fmt::format(
                     "Error: data is not a valid abcrypt encrypted file: {}",
                     error_message)
              << std::endl;
    abcrypt_params_free(params);
    return EXIT_FAILURE;
  }
  auto memory_cost = abcrypt_params_memory_cost(params);
  auto time_cost = abcrypt_params_time_cost(params);
  auto parallelism = abcrypt_params_parallelism(params);
  abcrypt_params_free(params);

  std::cout << fmt::format(
                   "Parameters used: memoryCost = {}; timeCost = {}; "
                   "parallelism = {};",
                   memory_cost, time_cost, parallelism)
            << std::endl;
}
