package vault

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	cryptProtectData   = crypt32.NewProc("CryptProtectData")
	cryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	localFree          = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")
)

func protectKey(raw []byte) ([]byte, error)    { return transformKey(raw, cryptProtectData) }
func unprotectKey(blob []byte) ([]byte, error) { return transformKey(blob, cryptUnprotectData) }

func transformKey(data []byte, proc *syscall.LazyProc) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%s: empty key data", proc.Name)
	}
	entropy := []byte("wc-prime")
	input := dataBlob{uint32(len(data)), &data[0]}
	optionalEntropy := dataBlob{uint32(len(entropy)), &entropy[0]}
	var output dataBlob
	// UI_FORBIDDEN, with no LOCAL_MACHINE flag, binds protection to this user.
	ok, _, err := proc.Call(uintptr(unsafe.Pointer(&input)), 0,
		uintptr(unsafe.Pointer(&optionalEntropy)), 0, 0, 0x1, uintptr(unsafe.Pointer(&output)))
	runtime.KeepAlive(data)
	runtime.KeepAlive(entropy)
	if output.pbData != nil {
		defer localFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	}
	if ok == 0 {
		return nil, fmt.Errorf("%s: %w", proc.Name, err)
	}
	return append([]byte(nil), unsafe.Slice(output.pbData, int(output.cbData))...), nil
}
