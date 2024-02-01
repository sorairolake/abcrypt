// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// An example of decrypting a file from the abcrypt encrypted data format.

#include <fmt/core.h>
#include <termios.h>
#include <unistd.h>

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
  CLI::App app{
      "An example of decrypting from the abcrypt encrypted data format"};
  std::optional<std::string> output_filename;
  app.add_option("-o,--output", output_filename, "Output the result to a file");
  app.set_version_flag("-V,--version", VERSION, "Print version");
  std::string input_filename;
  app.add_option("FILE", input_filename, "Input file")->required();
  CLI11_PARSE(app, argc, argv);

  std::ifstream input_file(input_filename);
  if (!input_file) {
    std::clog << fmt::format("Error: could not open {}: {}", input_filename,
                             std::strerror(errno))
              << std::endl;
    return EXIT_FAILURE;
  }
  std::vector<std::uint8_t> ciphertext(
      (std::istreambuf_iterator<char>(input_file)),
      std::istreambuf_iterator<char>());

  struct termios term;
  struct termios old_term;
  tcgetattr(STDIN_FILENO, &term);
  old_term = term;
  term.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &term);
  std::string passphrase;
  std::cout << "Enter passphrase: " << std::flush;
  std::cin >> passphrase;
  std::endl(std::cout);
  tcsetattr(STDIN_FILENO, TCSANOW, &old_term);

  std::vector<std::uint8_t> plaintext(ciphertext.size() -
                                      (ABCRYPT_HEADER_SIZE + ABCRYPT_TAG_SIZE));
  auto error_code =
      abcrypt_decrypt(ciphertext.data(), ciphertext.size(),
                      reinterpret_cast<uint8_t *>(passphrase.data()),
                      passphrase.size(), plaintext.data(), plaintext.size());
  if (error_code != ABCRYPT_ERROR_CODE_OK) {
    std::vector<std::uint8_t> buf(abcrypt_error_message_out_len(error_code));
    abcrypt_error_message(error_code, buf.data(), buf.size());
    std::string error_message(buf.cbegin(), buf.cend());
    switch (error_code) {
      case ABCRYPT_ERROR_CODE_INVALID_HEADER_MAC:
        std::clog << fmt::format("Error: passphrase is incorrect: {}",
                                 error_message)
                  << std::endl;
        break;
      case ABCRYPT_ERROR_CODE_INVALID_MAC:
        std::clog << fmt::format("Error: the encrypted data is corrupted: {}",
                                 error_message)
                  << std::endl;
        break;
      default:
        std::clog
            << fmt::format(
                   "Error: the header in the encrypted data is invalid: {}",
                   error_message)
            << std::endl;
        break;
    }
    return EXIT_FAILURE;
  }

  if (output_filename) {
    auto ofn = output_filename.value();
    std::ofstream output_file(ofn);
    if (!output_file) {
      std::clog << fmt::format("Error: could not open {}: {}", ofn,
                               std::strerror(errno))
                << std::endl;
      return EXIT_FAILURE;
    }
    std::copy(plaintext.cbegin(), plaintext.cend(),
              std::ostreambuf_iterator<char>(output_file));
  } else {
    std::copy(plaintext.cbegin(), plaintext.cend(),
              std::ostreambuf_iterator<char>(std::cout));
  }
}
