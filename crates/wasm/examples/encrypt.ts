#!/usr/bin/env -S deno run --allow-read --allow-write

// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { abcrypt, cli, command } from "./deps.ts";

import { VERSION } from "./version.ts";

const { args, options } = await new command.Command()
  .name("encrypt")
  .version(VERSION)
  .description("An example of encrypting to the abcrypt encrypted data format.")
  .option("-m, --memory-cost <NUM:integer>", "Set the memory size in KiB.", {
    default: 19456,
  })
  .option("-t, --time-cost <NUM:integer>", "Set the number of iterations.", {
    default: 2,
  })
  .option("-p, --parallelism <NUM:integer>", "Set the degree of parallelism.", {
    default: 1,
  })
  .arguments("<INFILE:file> <OUTFILE:file>")
  .parse();

const plaintext = Deno.readFileSync(args[0]);

const passphrase = new TextEncoder()
  .encode(cli.promptSecret("Enter passphrase: ")!);
const ciphertext = abcrypt.encryptWithParams(
  plaintext,
  passphrase,
  options.memoryCost,
  options.timeCost,
  options.parallelism,
);

Deno.writeFileSync(args[1], ciphertext);
