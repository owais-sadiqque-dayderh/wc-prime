//go:build !windows

package wifi

func wlanScan() error                      { return ErrUnsupported }
func wlanSetEapUserData(_, _ string) error { return ErrUnsupported }
