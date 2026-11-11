package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/sixban6/security-sentinel/internal/infra/config"
)

const (
	vaultEnvelopeVersion = 1
	vaultAAD             = "com.sixban6.security-sentinel.vault.v1"
	vaultMigratedFlagKey = "__migrated_v1"
)

type vaultEnvelope struct {
	Version int    `json:"v"`
	Salt    string `json:"salt"`
	Nonce   string `json:"nonce"`
	CT      string `json:"ct"`
}

var (
	ioregUUIDRe       = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)
	cachedMachineIDFn = sync.OnceValue(resolveMachineIdentity)
)

func vaultFilePath() string {
	return filepath.Join(config.ConfigDir(), "vault.enc")
}

// VaultFilePath returns the path to the hardware-bound AES-256-GCM encrypted vault file.
func VaultFilePath() string {
	return vaultFilePath()
}

func resolveMachineIdentity() string {
	hwID := ""
	switch runtime.GOOS {
	case "darwin":
		if out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
			if m := ioregUUIDRe.FindSubmatch(out); len(m) == 2 {
				hwID = strings.TrimSpace(string(m[1]))
			}
		}
		if hwID == "" {
			if out, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.uuid").Output(); err == nil {
				hwID = strings.TrimSpace(string(out))
			}
		}
	case "linux":
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
				hwID = strings.TrimSpace(string(b))
				break
			}
		}
	case "windows":
		hwID = strings.TrimSpace(os.Getenv("COMPUTERNAME") + "|" + os.Getenv("USERDOMAIN"))
	}
	if hwID == "" {
		if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
			hwID = strings.TrimSpace(h)
		} else {
			hwID = "sentinel-local-host"
		}
	}

	uidPart := strconv.Itoa(os.Getuid())
	if runtime.GOOS == "windows" {
		uidPart = os.Getenv("USERNAME")
	}
	return fmt.Sprintf("%s|uid=%s|goos=%s", hwID, uidPart, runtime.GOOS)
}

func deriveVaultKey(salt []byte, identity string) []byte {
	// RFC 5869 HKDF-SHA256 Extract & Expand (32-byte AES-256 key)
	ext := hmac.New(sha256.New, salt)
	ext.Write([]byte("security-sentinel-vault-ikm:"))
	ext.Write([]byte(identity))
	prk := ext.Sum(nil)

	exp := hmac.New(sha256.New, prk)
	exp.Write([]byte("security-sentinel-aes256gcm-key-v1"))
	exp.Write([]byte{0x01})
	return exp.Sum(nil)
}

func loadVaultMapWithIdentity(path, identity string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env vaultEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.Version != vaultEnvelopeVersion {
		return nil, fmt.Errorf("unsupported vault version %d", env.Version)
	}
	salt, err := base64.RawStdEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) < 16 {
		return nil, errors.New("invalid vault salt")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, errors.New("invalid vault nonce")
	}
	ct, err := base64.RawStdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, errors.New("invalid vault ciphertext")
	}

	key := deriveVaultKey(salt, identity)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid vault nonce size")
	}
	plain, err := gcm.Open(nil, nonce, ct, []byte(vaultAAD))
	if err != nil {
		return nil, fmt.Errorf("vault authentication failed (bound to a different machine or user): %w", err)
	}

	out := make(map[string]string)
	if err := json.Unmarshal(plain, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func saveVaultMapWithIdentity(path string, m map[string]string, identity string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if m == nil {
		m = make(map[string]string)
	}
	plain, err := json.Marshal(m)
	if err != nil {
		return err
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	key := deriveVaultKey(salt, identity)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nil, nonce, plain, []byte(vaultAAD))

	env := vaultEnvelope{
		Version: vaultEnvelopeVersion,
		Salt:    base64.RawStdEncoding.EncodeToString(salt),
		Nonce:   base64.RawStdEncoding.EncodeToString(nonce),
		CT:      base64.RawStdEncoding.EncodeToString(ct),
	}
	encoded, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
