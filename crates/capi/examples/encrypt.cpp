// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// An example of encrypting a file to the abcrypt encrypted data format.

#include <termios.h>
#include <unistd.h>

#include <CLI/CLI.hpp>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <format>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "abcrypt.h"
#include "version.hpp"

int main(int argc, char *argv[]) {
  CLI::App app{"An example of encrypting to the abcrypt encrypted data format"};
  std::uint32_t memory_cost{19456};
  app.add_option("-m,--memory-cost", memory_cost, "Set the memory size in KiB")
      ->capture_default_str();
  std::uint32_t time_cost{2};
  app.add_option("-t,--time-cost", time_cost, "Set the number of iterations")
      ->capture_default_str();
  std::uint32_t parallelism{1};
  app.add_option("-p,--parallelism", parallelism,
                 "Set the degree of parallelism")
      ->capture_default_str();
  app.set_version_flag("-V,--version", VERSION, "Print version");
  std::string input_filename;
  app.add_option("INFILE", input_filename, "Input file")->required();
  std::string output_filename;
  app.add_option("OUTFILE", output_filename, "Output file")->required();
  CLI11_PARSE(app, argc, argv);

  std::ifstream input_file(input_filename);
  if (!input_file) {
    std::clog << std::format("Error: could not open {}: {}", input_filename,
                             std::strerror(errno))
              << std::endl;
    return EXIT_FAILURE;
  }
  std::vector<std::uint8_t> plaintext(
      (std::istreambuf_iterator<char>(input_file)),
      std::istreambuf_iterator<char>());

  struct termios term;
  struct termios old_term;
  tcgetattr(STDIN_FILENO, &term);
  old_term = term;
  term.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &term);
  std::string passphrase;
  std::string confirm_passphrase;
  do {
    std::cout << "Enter passphrase: " << std::flush;
    std::cin >> passphrase;
    std::endl(std::cout);
    std::cout << "Confirm passphrase: " << std::flush;
    std::cin >> confirm_passphrase;
    std::endl(std::cout);
    if (passphrase != confirm_passphrase) {
      std::clog << "Passphrases mismatch, try again" << std::endl;
    }
  } while (passphrase != confirm_passphrase);
  tcsetattr(STDIN_FILENO, TCSANOW, &old_term);

  std::vector<std::uint8_t> ciphertext(
      plaintext.size() + (ABCRYPT_HEADER_SIZE + ABCRYPT_TAG_SIZE));
  auto error_code = abcrypt_encrypt_with_params(
      plaintext.data(), plaintext.size(),
      reinterpret_cast<uint8_t *>(passphrase.data()), passphrase.size(),
      ciphertext.data(), ciphertext.size(), memory_cost, time_cost,
      parallelism);
  if (error_code != ABCRYPT_ERROR_CODE_OK) {
    std::vector<std::uint8_t> buf(abcrypt_error_message_out_len(error_code));
    abcrypt_error_message(error_code, buf.data(), buf.size());
    std::string error_message(buf.cbegin(), buf.cend());
    std::clog << std::format("Error: {}", error_message) << std::endl;
    return EXIT_FAILURE;
  }

  std::ofstream output_file(output_filename);
  if (!output_file) {
    std::clog << std::format("Error: could not open {}: {}", output_filename,
                             std::strerror(errno))
              << std::endl;
    return EXIT_FAILURE;
  }
  std::copy(ciphertext.cbegin(), ciphertext.cend(),
            std::ostreambuf_iterator<char>(output_file));
}
