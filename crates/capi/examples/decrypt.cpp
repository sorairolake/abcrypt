// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// An example of decrypting a file from the abcrypt encrypted data format.

#include <fmt/core.h>
#include <termios.h>
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
  std::cout << "Usage: decrypt <INFILE> <OUTFILE>\n\n";
  std::cout << "Arguments:\n";
  std::cout << "  <INFILE>   File to decrypt\n";
  std::cout << "  <OUTFILE>  File to write the result to\n\n";
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
  char *output_filename;
  if ((argc - optind) == 2) {
    input_filename = argv[optind];
    output_filename = argv[optind + 1];
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
    std::string error_message(std::cbegin(buf), std::cend(buf));
    switch (error_code) {
      case ABCRYPT_ERROR_CODE_INVALID_HEADER_MAC:
        std::clog << fmt::format("Error: passphrase is incorrect: {}",
                                 error_message)
                  << std::endl;
        break;
      case ABCRYPT_ERROR_CODE_INVALID_MAC:
        std::clog << fmt::format("Error: {} is corrupted: {}", input_filename,
                                 error_message)
                  << std::endl;
        break;
      default:
        std::clog << fmt::format("Error: the header in {} is invalid: {}",
                                 input_filename, error_message)
                  << std::endl;
        break;
    }
    return EXIT_FAILURE;
  }

  std::ofstream output_file(output_filename);
  if (!input_file) {
    std::clog << fmt::format("Error: could not open {}: {}", output_filename,
                             std::strerror(errno))
              << std::endl;
    return EXIT_FAILURE;
  }
  std::ostreambuf_iterator<char> output_file_iter(output_file);
  std::copy(std::cbegin(plaintext), std::cend(plaintext), output_file_iter);
}
