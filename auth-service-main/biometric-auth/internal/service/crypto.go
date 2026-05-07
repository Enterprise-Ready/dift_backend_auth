package service

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"biometric-auth/internal/config"

	"golang.org/x/crypto/argon2"
)

// CryptoService handles all cryptographic operations.
type CryptoService struct {
	cfg *config.Config
}

func NewCryptoService(cfg *config.Config) *CryptoService {
	return &CryptoService{cfg: cfg}
}

// ─── Random ──────────────────────────────────────────────────────────────────

// RandomBytes generates cryptographically secure random bytes.
func (s *CryptoService) RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}
	return b, nil
}

func (s *CryptoService) RandomBase64URL(n int) (string, error) {
	b, err := s.RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *CryptoService) RandomHex(n int) (string, error) {
	b, err := s.RandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ─── Argon2id Password Hashing ───────────────────────────────────────────────

func (s *CryptoService) HashPassword(password string) (string, error) {
	salt, err := s.RandomBytes(16)
	if err != nil {
		return "", fmt.Errorf("salt generation: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		s.cfg.HashIterations,
		s.cfg.HashMemory,
		s.cfg.HashParallelism,
		s.cfg.HashKeyLength,
	)

	// Format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	encoded := fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		s.cfg.HashMemory,
		s.cfg.HashIterations,
		s.cfg.HashParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

func (s *CryptoService) VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid hash format")
	}

	var memory, iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, fmt.Errorf("parse params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(hash, expectedHash) == 1, nil
}

// ─── HMAC ────────────────────────────────────────────────────────────────────

// HMACChallenge creates HMAC-SHA256 over challenge fields.
// Prevents challenge tampering — server verifies before accepting signature.
func (s *CryptoService) HMACChallenge(nonce, deviceID string, action string, expiry time.Time) string {
	msg := nonce + "|" + deviceID + "|" + action + "|" + fmt.Sprintf("%d", expiry.Unix())
	mac := hmac.New(sha256.New, []byte(s.cfg.ChallengeSecret))
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *CryptoService) VerifyHMACChallenge(nonce, deviceID, action string, expiry time.Time, sig string) bool {
	expected := s.HMACChallenge(nonce, deviceID, action, expiry)
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	expectedBytes, _ := base64.RawURLEncoding.DecodeString(expected)
	return hmac.Equal(sigBytes, expectedBytes)
}

// HashToken hashes a token for secure storage (prevent token DB leakage).
func (s *CryptoService) HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// HashFingerprint one-way hash of device fingerprint.
func (s *CryptoService) HashFingerprint(fp string) string {
	h := sha256.Sum256([]byte(fp))
	return hex.EncodeToString(h[:])
}

// ─── Public Key Verification ─────────────────────────────────────────────────

// ParseECDSAPublicKey parses PEM-encoded ECDSA public key (P-256 / ES256).
func (s *CryptoService) ParseECDSAPublicKey(pemKey string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not ECDSA")
	}

	if ecKey.Curve != elliptic.P256() {
		return nil, errors.New("only P-256 curve accepted")
	}

	return ecKey, nil
}

// ParseRSAPublicKey parses PEM-encoded RSA public key.
func (s *CryptoService) ParseRSAPublicKey(pemKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not RSA")
	}

	if rsaKey.N.BitLen() < 2048 {
		return nil, errors.New("RSA key must be at least 2048 bits")
	}

	return rsaKey, nil
}

// VerifyECDSASignature verifies an ECDSA signature over payload.
// payload = SHA256(nonce + deviceID + action + timestamp)
// signature = base64url(r || s) — raw 64 bytes for ES256
func (s *CryptoService) VerifyECDSASignature(pubKey *ecdsa.PublicKey, payload []byte, sigB64 string) error {
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if len(sigBytes) != 64 {
		return fmt.Errorf("invalid ES256 signature length: got %d, want 64", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	rr := new(big.Int).SetBytes(sigBytes[32:])

	digest := sha256.Sum256(payload)

	if !ecdsa.Verify(pubKey, digest[:], r, rr) {
		return errors.New("signature verification failed")
	}
	return nil
}

// VerifyRSASignature verifies RSA-PSS signature.
func (s *CryptoService) VerifyRSASignature(pubKey *rsa.PublicKey, payload []byte, sigB64 string) error {
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	digest := sha256.Sum256(payload)
	err = rsa.VerifyPSS(pubKey, crypto.SHA256, digest[:], sigBytes, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	if err != nil {
		return fmt.Errorf("RSA-PSS verification failed: %w", err)
	}
	return nil
}

// BuildSignedPayload constructs the canonical payload that the mobile app should sign.
// Format: nonce + "." + deviceID + "." + action + "." + unixTimestamp
// This is hashed with SHA-256 before signing on device.
func (s *CryptoService) BuildSignedPayload(nonce, deviceID, action string, ts int64) []byte {
	raw := fmt.Sprintf("%s.%s.%s.%d", nonce, deviceID, action, ts)
	return []byte(raw)
}

// VerifySignatureForAlgo dispatches to ECDSA or RSA based on stored key type.
func (s *CryptoService) VerifySignatureForAlgo(algo, pubKeyPEM string, payload []byte, sigB64 string) error {
	switch algo {
	case "ES256":
		pubKey, err := s.ParseECDSAPublicKey(pubKeyPEM)
		if err != nil {
			return fmt.Errorf("parse ECDSA key: %w", err)
		}
		return s.VerifyECDSASignature(pubKey, payload, sigB64)

	case "RS256":
		pubKey, err := s.ParseRSAPublicKey(pubKeyPEM)
		if err != nil {
			return fmt.Errorf("parse RSA key: %w", err)
		}
		return s.VerifyRSASignature(pubKey, payload, sigB64)

	default:
		return fmt.Errorf("unsupported algorithm: %s", algo)
	}
}

// ValidatePublicKeyFormat ensures PEM is well-formed before storage.
func (s *CryptoService) ValidatePublicKeyFormat(pemKey, algo string) error {
	switch algo {
	case "ES256":
		_, err := s.ParseECDSAPublicKey(pemKey)
		return err
	case "RS256":
		_, err := s.ParseRSAPublicKey(pemKey)
		return err
	default:
		return fmt.Errorf("unsupported algorithm: %s", algo)
	}
}
