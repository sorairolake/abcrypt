#!/usr/bin/env -S deno run --allow-read

// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { abcrypt, command, io } from "./deps.ts";

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
  `Parameters used: m_cost = ${params.mCost}; t_cost = ${params.tCost}; p_cost = ${params.pCost};`,
);
