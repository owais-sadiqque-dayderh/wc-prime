package main

import (
	"os"
	"syscall"
)

// The Windows build uses the GUI subsystem so the background service never
// shows a console window. When run from a terminal (e.g. `wcprime url`),
// attach to the parent console so output is still visible.
func init() {
	if h, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE); err == nil && h != 0 && h != syscall.InvalidHandle {
		return // stdout already redirected to a file or pipe
	}
	const attachParentProcess = ^uintptr(0) // (DWORD)-1
	attach := syscall.NewLazyDLL("kernel32.dll").NewProc("AttachConsole")
	if r, _, _ := attach.Call(attachParentProcess); r == 0 {
		return // no parent console (started by Task Scheduler)
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
	}
}
