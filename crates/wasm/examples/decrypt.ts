#!/usr/bin/env -S deno run --allow-read --allow-write

// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

import * as cli from "@std/cli";
import * as io from "@std/io";

import * as command from "@cliffy/command";

import * as abcrypt from "../pkg/abcrypt_wasm.js";

import { VERSION } from "./version.ts";

const { args, options } = await new command.Command()
  .name("decrypt")
  .version(VERSION)
  .description(
    "An example of decrypting from the abcrypt encrypted data format.",
  )
  .option("-o, --output <FILE:file>", "Output the result to a file.")
  .arguments("<FILE:file>")
  .parse();

const ciphertext = Deno.readFileSync(args[0]);

const passphrase = new TextEncoder()
  .encode(cli.promptSecret("Enter passphrase: ")!);
const plaintext = abcrypt.decrypt(ciphertext, passphrase);

if (options.output === undefined) {
  io.writeAllSync(Deno.stdout, plaintext);
} else {
  Deno.writeFileSync(options.output, plaintext);
}
