package wifi

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	wlanapi                      = syscall.NewLazyDLL("wlanapi.dll")
	procWlanOpenHandle           = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle          = wlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces       = wlanapi.NewProc("WlanEnumInterfaces")
	procWlanFreeMemory           = wlanapi.NewProc("WlanFreeMemory")
	procWlanScan                 = wlanapi.NewProc("WlanScan")
	procWlanSetProfileEapXmlUser = wlanapi.NewProc("WlanSetProfileEapXmlUserData")
)

type guid [16]byte

// WLAN_INTERFACE_INFO: GUID (16) + WCHAR[256] (512) + state (4).
const wlanInterfaceInfoSize = 16 + 512 + 4

// withInterfaces opens a WLAN client handle and calls fn for every interface.
func withInterfaces(fn func(h uintptr, g *guid) error) error {
	var h uintptr
	var negotiated uint32
	if r, _, _ := procWlanOpenHandle.Call(2, 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&h))); r != 0 {
		return fmt.Errorf("WlanOpenHandle: %w", syscall.Errno(r))
	}
	defer procWlanCloseHandle.Call(h, 0)

	var list unsafe.Pointer
	if r, _, _ := procWlanEnumInterfaces.Call(h, 0, uintptr(unsafe.Pointer(&list))); r != 0 {
		return fmt.Errorf("WlanEnumInterfaces: %w", syscall.Errno(r))
	}
	defer procWlanFreeMemory.Call(uintptr(list))

	n := *(*uint32)(list)
	if n == 0 {
		return errors.New("no WLAN interface")
	}
	var firstErr error
	for i := uintptr(0); i < uintptr(n); i++ {
		g := (*guid)(unsafe.Add(list, 8+i*wlanInterfaceInfoSize))
		if err := fn(h, g); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func wlanScan() error {
	return withInterfaces(func(h uintptr, g *guid) error {
		if r, _, _ := procWlanScan.Call(h, uintptr(unsafe.Pointer(g)), 0, 0, 0); r != 0 {
			return fmt.Errorf("WlanScan: %w", syscall.Errno(r))
		}
		return nil
	})
}

func wlanSetEapUserData(profile, userXML string) error {
	p, err := syscall.UTF16PtrFromString(profile)
	if err != nil {
		return err
	}
	x, err := syscall.UTF16PtrFromString(userXML)
	if err != nil {
		return err
	}
	return withInterfaces(func(h uintptr, g *guid) error {
		r, _, _ := procWlanSetProfileEapXmlUser.Call(h, uintptr(unsafe.Pointer(g)),
			uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(x)), 0)
		if r != 0 {
			return fmt.Errorf("WlanSetProfileEapXmlUserData: %w", syscall.Errno(r))
		}
		return nil
	})
}
