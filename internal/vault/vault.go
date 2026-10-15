package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/owais-sadiqque-dayderh/wc-prime/internal/portal"
	"github.com/owais-sadiqque-dayderh/wc-prime/internal/wifi"
)

const vaultAAD = "wc-prime vault v1"

type diskVault struct {
	Version  int       `json:"version"`
	Networks []Network `json:"networks"`
}

// Vault protects credentials at rest and in backups/sync copies of vault.bin
// alone. Anyone running as the same OS user can decrypt it. Secrets never leave
// this process except to the OS Wi-Fi stack or the captive portal.
type Vault struct {
	mu       sync.RWMutex
	dir      string
	aead     cipher.AEAD
	networks []Network
	version  uint64
}

// Open loads (or creates) the vault in dir. dir is created 0700 if missing.
func Open(dir string) (*Vault, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "vault.bin"))
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read vault: %w", err)
	}
	keyPath := filepath.Join(dir, "vault.key")
	blob, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) && !exists {
		raw := make([]byte, 32)
		if _, err = rand.Read(raw); err != nil {
			return nil, fmt.Errorf("generate vault key: %w", err)
		}
		blob, err = protectKey(raw)
		if err != nil {
			return nil, fmt.Errorf("protect vault key: %w", err)
		}
		f, createErr := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(createErr, os.ErrExist) {
			blob, err = os.ReadFile(keyPath)
		} else if createErr != nil {
			err = createErr
		} else {
			_, err = f.Write(blob)
			if err == nil {
				err = f.Sync()
			}
			closeErr := f.Close()
			if err == nil {
				err = closeErr
			}
			if err != nil {
				_ = os.Remove(keyPath)
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read/create vault key: %w", err)
	}
	key, err := unprotectKey(blob)
	if err != nil {
		return nil, fmt.Errorf("unprotect vault key: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("vault key must contain 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	v := &Vault{dir: dir, aead: aead, networks: []Network{}}
	if !exists {
		if err := v.persist(v.networks); err != nil {
			return nil, err
		}
		return v, nil
	}
	if len(data) < 4+aead.NonceSize()+aead.Overhead() || string(data[:4]) != "WCV1" {
		return nil, errors.New("invalid vault file header or length")
	}
	plain, err := aead.Open(nil, data[4:4+aead.NonceSize()], data[4+aead.NonceSize():], []byte(vaultAAD))
	if err != nil {
		return nil, fmt.Errorf("decrypt vault (wrong key or corrupt file): %w", err)
	}
	var disk diskVault
	if err := json.Unmarshal(plain, &disk); err != nil {
		return nil, fmt.Errorf("decode vault: %w", err)
	}
	if disk.Version != 1 {
		return nil, fmt.Errorf("unsupported vault version %d", disk.Version)
	}
	ids, ssids := map[string]bool{}, map[string]bool{}
	for i, n := range disk.Networks {
		if n.ID == "" || ids[n.ID] {
			return nil, errors.New("invalid or duplicate network ID in vault")
		}
		n, err = normalize(n)
		if err != nil {
			return nil, fmt.Errorf("invalid network in vault: %w", err)
		}
		if ssids[n.SSID] {
			return nil, errors.New("duplicate SSID in vault")
		}
		ids[n.ID], ssids[n.SSID] = true, true
		disk.Networks[i] = n
	}
	v.networks = disk.Networks
	return v, nil
}

func clone(n Network) Network {
	if n.Extra != nil {
		extra := make(map[string]string, len(n.Extra))
		for k, v := range n.Extra {
			extra[k] = v
		}
		n.Extra = extra
	}
	if n.PortalHosts != nil {
		n.PortalHosts = append([]string(nil), n.PortalHosts...)
	}
	return n
}

func (v *Vault) List() []Network {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]Network, len(v.networks))
	for i, n := range v.networks {
		out[i] = clone(n)
	}
	return out
}

func (v *Vault) Get(id string) (Network, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, n := range v.networks {
		if n.ID == id {
			return clone(n), true
		}
	}
	return Network{}, false
}

// FindSSID returns the first exact SSID match in priority order.
func (v *Vault) FindSSID(ssid string) (Network, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, n := range v.networks {
		if n.SSID == ssid {
			return clone(n), true
		}
	}
	return Network{}, false
}

func normalize(n Network) (Network, error) {
	n.SSID = strings.TrimSpace(n.SSID)
	if n.SSID == "" {
		return n, errors.New("SSID is required")
	}
	if len(n.SSID) > 32 {
		return n, errors.New("SSID must be at most 32 bytes")
	}
	if n.Security == "" {
		n.Security = wifi.Open
	}
	switch n.Security {
	case wifi.Open:
		n.Passphrase = ""
	case wifi.PSK, wifi.SAE:
		if size := utf8.RuneCountInString(n.Passphrase); size < 8 || size > 63 {
			return n, errors.New("Wi-Fi passphrase must be 8–63 characters")
		}
	case wifi.Enterprise:
		n.Passphrase = ""
		if n.Username == "" || n.Password == "" {
			return n, errors.New("enterprise Wi-Fi requires a username and password")
		}
		n.DomainMatch = strings.TrimSpace(n.DomainMatch)
		if n.DomainMatch == "" {
			return n, errors.New("enterprise Wi-Fi requires the RADIUS server domain so the network can be verified (ask your IT desk, e.g. radius.example.edu)")
		}
	default:
		return n, fmt.Errorf("unsupported Wi-Fi security %q", n.Security)
	}
	if n.Security != wifi.Enterprise {
		n.EAP, n.Phase2, n.AnonymousIdentity, n.CACert, n.DomainMatch = "", "", "", "", ""
	}
	if n.Portal {
		if n.Username == "" {
			return n, errors.New("captive portal requires a username")
		}
		if n.PortalURL != "" {
			u, err := url.Parse(n.PortalURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
				return n, errors.New("portal URL must be an absolute http or https URL")
			}
		}
		hosts := n.PortalHosts[:0:0]
		for _, h := range n.PortalHosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			if portal.ValidateTrustedHost(h) != nil {
				return n, fmt.Errorf("trusted portal host %q must be a host name, *.domain, or an origin like https://login.example.org", h)
			}
			hosts = append(hosts, h)
		}
		n.PortalHosts = hosts
		if n.PortalURL == "" && len(n.PortalHosts) == 0 {
			return n, errors.New("captive portal requires a login URL or at least one trusted portal host, so credentials are only sent to the real login page")
		}
	} else {
		n.PortalURL, n.UserField, n.PassField, n.Extra, n.InsecureTLS = "", "", "", nil, false
		n.PortalHosts = nil
	}
	return n, nil
}

func (v *Vault) Save(n Network) (Network, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	index := -1
	if n.ID != "" {
		for i, old := range v.networks {
			if old.ID == n.ID {
				index = i
				if n.Passphrase == "" {
					n.Passphrase = old.Passphrase
				}
				if n.Password == "" {
					n.Password = old.Password
				}
				break
			}
		}
		if index < 0 {
			return Network{}, fmt.Errorf("network %q does not exist", n.ID)
		}
	} else {
		for {
			raw := make([]byte, 8)
			if _, err := rand.Read(raw); err != nil {
				return Network{}, fmt.Errorf("generate network ID: %w", err)
			}
			n.ID = hex.EncodeToString(raw)
			duplicate := false
			for _, old := range v.networks {
				if old.ID == n.ID {
					duplicate = true
					break
				}
			}
			if !duplicate {
				break
			}
		}
	}
	var err error
	n, err = normalize(n)
	if err != nil {
		return Network{}, err
	}
	for _, old := range v.networks {
		if old.ID != n.ID && old.SSID == n.SSID {
			return Network{}, fmt.Errorf("SSID %q is already saved", n.SSID)
		}
	}
	next := append([]Network(nil), v.networks...)
	n = clone(n)
	if index < 0 {
		next = append(next, n)
	} else {
		next[index] = n
	}
	if err := v.commit(next); err != nil {
		return Network{}, err
	}
	return clone(n), nil
}

func (v *Vault) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i, n := range v.networks {
		if n.ID == id {
			next := make([]Network, 0, len(v.networks)-1)
			next = append(next, v.networks[:i]...)
			next = append(next, v.networks[i+1:]...)
			return v.commit(next)
		}
	}
	return fmt.Errorf("network %q does not exist", id)
}

func (v *Vault) Reorder(ids []string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(ids) != len(v.networks) {
		return errors.New("reorder must contain every network ID exactly once")
	}
	byID := make(map[string]Network, len(v.networks))
	for _, n := range v.networks {
		byID[n.ID] = n
	}
	next := make([]Network, 0, len(ids))
	for _, id := range ids {
		n, ok := byID[id]
		if !ok {
			return errors.New("reorder must contain every network ID exactly once")
		}
		next = append(next, n)
		delete(byID, id)
	}
	return v.commit(next)
}

// Version counts successful mutations during this Vault's lifetime.
func (v *Vault) Version() uint64 { v.mu.RLock(); defer v.mu.RUnlock(); return v.version }

func (v *Vault) commit(next []Network) error {
	// Publish only after persistence succeeds, so failed writes leave memory intact.
	if err := v.persist(next); err != nil {
		return err
	}
	v.networks = next
	v.version++
	return nil
}

func (v *Vault) persist(networks []Network) error {
	plain, err := json.Marshal(diskVault{Version: 1, Networks: networks})
	if err != nil {
		return fmt.Errorf("encode vault: %w", err)
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate vault nonce: %w", err)
	}
	data := append([]byte("WCV1"), nonce...)
	data = v.aead.Seal(data, nonce, plain, []byte(vaultAAD))
	f, err := os.CreateTemp(v.dir, ".vault-*")
	if err != nil {
		return fmt.Errorf("create vault temporary file: %w", err)
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(v.dir, "vault.bin"))
	}
	if err != nil {
		return fmt.Errorf("write vault: %w", err)
	}
	return nil
}
