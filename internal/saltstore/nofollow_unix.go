// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// internal/saltstore/nofollow_unix.go — open flag that refuses symbolic links.
//
// Defines openNoFollow, the extra os.OpenFile flag the file backends add so
// that a symbolic link at the target path is refused. On Unix systems the
// value is syscall.O_NOFOLLOW.
package saltstore

import "syscall"

// openNoFollow is OR-ed into the flag argument of os.OpenFile. It makes the
// open call fail when the final path component is a symbolic link.
const openNoFollow = syscall.O_NOFOLLOW
