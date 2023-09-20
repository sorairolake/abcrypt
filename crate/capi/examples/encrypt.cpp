// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// An example of encrypting a file to the abcrypt encrypted data format.

#include <fmt/core.h>
#include <termios.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "abcrypt.h"
#include "version.hpp"

static void print_help(void) {
  std::cout << "Usage: encrypt [OPTIONS] <INFILE> <OUTFILE>\n\n";
  std::cout << "Arguments:\n";
  std::cout << "  <INFILE>   File to encrypt\n";
  std::cout << "  <OUTFILE>  File to write the result to\n\n";
  std::cout << "Options:\n";
  std::cout << "  -m <NUM>  Set the memory size in KiB [default: 19456]\n";
  std::cout << "  -t <NUM>  Set the number of iterations [default: 2]\n";
  std::cout << "  -p <NUM>  Set the degree of parallelism [default: 1]\n";
  std::cout << "  -h        Print help\n";
  std::cout << "  -V        Print version" << std::endl;
}

int main(int argc, char *argv[]) {
  std::uint32_t memory_size = 19456;
  std::uint32_t iterations = 2;
  std::uint32_t parallelism = 1;

  int opt;
  while ((opt = getopt(argc, argv, "m:t:p:hV")) != -1) {
    switch (opt) {
      case 'm':
        memory_size = std::atoi(optarg);
        break;
      case 't':
        iterations = std::atoi(optarg);
        break;
      case 'p':
        parallelism = std::atoi(optarg);
        break;
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
  switch (argc - optind) {
    case 0:
    case 1:
      std::clog
          << "Error: the following required arguments were not provided:\n";
      if ((argc - optind) == 0) {
        std::clog << "  <INFILE>\n";
      }
      std::clog << "  <OUTFILE>\n\n";
      std::clog << "Usage: encrypt [OPTIONS] <INFILE> <OUTFILE>\n\n";
      std::clog << "For more information, try '-h'." << std::endl;
      return EXIT_FAILURE;
    case 2:
      input_filename = argv[optind];
      output_filename = argv[optind + 1];
      break;
    default:
      std::clog << fmt::format("Error: unexpected argument '{}' found\n\n",
                               argv[optind + 2]);
      std::clog << "Usage: encrypt [OPTIONS] <INFILE> <OUTFILE>\n\n";
      std::clog << "For more information, try '-h'." << std::endl;
      return EXIT_FAILURE;
  }

  std::ifstream input_file(input_filename);
  if (!input_file) {
    std::clog << fmt::format("Error: could not open {}", input_filename)
              << std::endl;
    return EXIT_FAILURE;
  }
  std::vector<std::uint8_t> plaintext(
      (std::istreambuf_iterator<char>(input_file)),
      std::istreambuf_iterator<char>());
  if (!input_file) {
    std::clog << fmt::format("Error: could not read data from {}",
                             input_filename)
              << std::endl;
    return EXIT_FAILURE;
  }

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
      ciphertext.data(), ciphertext.size(), memory_size, iterations,
      parallelism);
  if (error_code != ABCRYPT_ERROR_CODE_OK) {
    std::vector<std::uint8_t> buf(abcrypt_error_message_out_len(error_code));
    abcrypt_error_message(error_code, buf.data(), buf.size());
    std::string error_message(std::cbegin(buf), std::cend(buf));
    std::clog << fmt::format("Error: {}", error_message) << std::endl;
    return EXIT_FAILURE;
  }

  std::ofstream output_file(output_filename);
  if (!input_file) {
    std::clog << fmt::format("Error: could not open {}", output_filename)
              << std::endl;
    return EXIT_FAILURE;
  }
  std::ostreambuf_iterator<char> output_file_iter(output_file);
  std::copy(std::cbegin(ciphertext), std::cend(ciphertext), output_file_iter);
  if (!input_file) {
    std::clog << fmt::format("Error: could not write the result to {}",
                             output_filename)
              << std::endl;
    return EXIT_FAILURE;
  }
}
