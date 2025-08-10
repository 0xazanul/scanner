package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// Dir returns the cache directory path, creating it if needed.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".smartscanner", "cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// Key computes a unique key filename using inputs (e.g., file hash + tool tag)
func Key(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func Load(key string) ([]byte, bool) {
	dir, err := Dir()
	if err != nil {
		return nil, false
	}
	path := filepath.Join(dir, key)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return b, true
}

func Store(key string, data []byte) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, key)
	return os.WriteFile(path, data, 0o644)
}
