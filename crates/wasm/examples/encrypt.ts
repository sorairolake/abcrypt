// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

import * as cli from "https://deno.land/std@0.212.0/cli/mod.ts";

import * as abcrypt from "../pkg/abcrypt_wasm.js";

const opt = cli.parseArgs(Deno.args);

const plaintext = Deno.readFileSync(opt._[0].toString());

const passphrase = new TextEncoder().encode(
  cli.promptSecret("Enter passphrase: ")!,
);
const ciphertext = abcrypt.encrypt_with_params(
  plaintext,
  passphrase,
  opt.m ?? 19456,
  opt.t ?? 2,
  opt.p ?? 1,
);

Deno.writeFileSync(opt._[1].toString(), ciphertext);
