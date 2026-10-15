//go:build !windows

package vault

func protectKey(raw []byte) ([]byte, error)    { return append([]byte(nil), raw...), nil }
func unprotectKey(blob []byte) ([]byte, error) { return append([]byte(nil), blob...), nil }
