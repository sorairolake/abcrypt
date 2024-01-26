// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

import * as abcrypt from "../pkg/abcrypt_wasm.js";

const ciphertext = Deno.readFileSync(Deno.args[0]);

const params = abcrypt.Params.new(ciphertext);
console.log(
  `Parameters used: m_cost = ${params.m_cost}; t_cost = ${params.t_cost}; p_cost = ${params.p_cost};`,
);
