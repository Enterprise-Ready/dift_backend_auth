//go:build legacy
// +build legacy

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	DefaultBcryptCost = 12
	APIKeyPrefix      = "aek_"
	APIKeyLength      = 32
)

// ─── Password ─────────────────────────────────────────────────────────────────

func HashPassword(password string, cost int) (string, error) {
	if cost == 0 {
		cost = DefaultBcryptCost
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(bytes), err
}

func VerifyPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ─── OTP ─────────────────────────────────────────────────────────────────────

func GenerateOTP(length int) (string, error) {
	if length == 0 {
		length = 6
	}
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", length, n.Int64()), nil
}

// ─── API Key ──────────────────────────────────────────────────────────────────

func GenerateAPIKey() (plaintext, hash string, err error) {
	b := make([]byte, APIKeyLength)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	raw := base64.URLEncoding.EncodeToString(b)
	plaintext = APIKeyPrefix + raw
	h := sha256.Sum256([]byte(plaintext))
	hash = hex.EncodeToString(h[:])
	return plaintext, hash, nil
}

func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func ExtractAPIKeyPrefix(key string) string {
	if !strings.HasPrefix(key, APIKeyPrefix) {
		return ""
	}
	raw := key[len(APIKeyPrefix):]
	if len(raw) < 8 {
		return ""
	}
	return APIKeyPrefix + raw[:8]
}

// ─── AES-GCM Encryption ───────────────────────────────────────────────────────

func Encrypt(plaintext, key string) (string, error) {
	k := sha256KeyFromString(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(ciphertext64, key string) (string, error) {
	k := sha256KeyFromString(key)
	data, err := base64.StdEncoding.DecodeString(ciphertext64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func sha256KeyFromString(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// ─── Secure Token ─────────────────────────────────────────────────────────────

func GenerateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func GenerateBackupCodes(count int) ([]string, []string, error) {
	codes := make([]string, count)
	hashes := make([]string, count)
	for i := 0; i < count; i++ {
		b := make([]byte, 5)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		code := fmt.Sprintf("%X-%X", b[:3], b[3:])
		codes[i] = code
		h := sha256.Sum256([]byte(code))
		hashes[i] = hex.EncodeToString(h[:])
	}
	return codes, hashes, nil
}

func HashBackupCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}
