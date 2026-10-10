// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

//go:build windows

// internal/saltstore/nofollow_windows.go — open flag that refuses symbolic links.
//
// Defines openNoFollow for Windows. The syscall package has no O_NOFOLLOW
// constant on Windows, so the value is zero and the open call does not refuse
// symbolic links there. The other controls (mode bits, O_EXCL) still apply.
package saltstore

// openNoFollow is OR-ed into the flag argument of os.OpenFile. It is zero on
// Windows because the platform has no O_NOFOLLOW flag.
const openNoFollow = 0
