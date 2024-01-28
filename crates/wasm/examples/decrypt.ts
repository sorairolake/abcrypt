// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

import * as cli from "https://deno.land/std@0.213.0/cli/mod.ts";

import * as abcrypt from "../pkg/abcrypt_wasm.js";

const ciphertext = Deno.readFileSync(Deno.args[0]);

const passphrase = new TextEncoder().encode(
  cli.promptSecret("Enter passphrase: ")!,
);
const plaintext = abcrypt.decrypt(ciphertext, passphrase);

Deno.writeFileSync(Deno.args[1], plaintext);
