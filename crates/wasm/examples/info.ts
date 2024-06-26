#!/usr/bin/env -S deno run --allow-read

// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

import * as io from "@std/io";

import * as command from "@cliffy/command";

import * as abcrypt from "../pkg/abcrypt_wasm.js";

import { VERSION } from "./version.ts";

const { args } = await new command.Command()
  .name("info")
  .version(VERSION)
  .description("An example of reading the Argon2 parameters.")
  .arguments("[FILE:file]")
  .parse();

const ciphertext = args[0] === undefined
  ? io.readAllSync(Deno.stdin)
  : Deno.readFileSync(args[0]);

const params = new abcrypt.Params(ciphertext);
console.log(
  `Parameters used: memoryCost = ${params.memoryCost}; timeCost = ${params.timeCost}; parallelism = ${params.parallelism};`,
);
