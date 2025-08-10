package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Fingerprint computes a stable hash for a finding key
func Fingerprint(ruleID, file string, start, end int, context string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%d|%d|%s", ruleID, file, start, end, context)
	return hex.EncodeToString(h.Sum(nil))
}
