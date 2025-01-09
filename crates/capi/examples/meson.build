# SPDX-FileCopyrightText: 2023 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

project('abcrypt_capi_examples',
  'cpp',
  default_options: ['warning_level=3', 'cpp_std=c++20'],
  license: 'Apache-2.0 OR MIT',
  meson_version: '>=0.53.0',
  version: '0.3.2',
)

fs = import('fs')

cpp = meson.get_compiler('cpp')
cpp.check_header('termios.h', required: true)
cpp.check_header('unistd.h', required: true)

deps = dependency('CLI11')

libdir = meson.current_source_dir() / '../../../target'
if fs.exists(libdir / 'release')
  libdir = libdir / 'release'
else
  libdir = libdir / 'debug'
endif
libabcrypt_capi = cpp.find_library('libabcrypt_capi', dirs: libdir, static: true)
incdir = include_directories('../include')

example_names = ['encrypt', 'decrypt', 'info']
foreach example_name : example_names
  executable(example_name,
    example_name + '.cpp',
    dependencies: [deps, libabcrypt_capi],
    include_directories: incdir,
  )
endforeach
