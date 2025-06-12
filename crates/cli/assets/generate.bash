#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2025 Shun Sakai
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euxCo pipefail

scriptDir=$(cd "$(dirname "$0")" && pwd)
cd "$scriptDir"

autocast --overwrite demo.yaml demo.cast
agg --font-family "Cascadia Code,Hack,Source Code Pro" demo.cast demo.gif
gifsicle -b -O3 demo.gif
