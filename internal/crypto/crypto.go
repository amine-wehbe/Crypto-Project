package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

func TestCrypto() {
	fmt.Println("Crypto package working ✅")
}

// DeriveKEK derives a Key Encryption Key (KEK) using Argon2id.
func DeriveKEK(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemory, uint8(argonThreads), argonKeyLen)
}

// GenerateRandomBytes returns a securely-generated random byte slice.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// WrapKey encrypts a DEK using a KEK and AES-GCM.
func WrapKey(kek []byte, dek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := GenerateRandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, dek, nil)
	return append(nonce, ct...), nil
}

// UnwrapKey decrypts the wrapped DEK using the KEK and AES-GCM.
func UnwrapKey(kek []byte, wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(wrapped) < ns {
		return nil, errors.New("wrapped key too short")
	}
	nonce := wrapped[:ns]
	ct := wrapped[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

// EncryptEntry encrypts plaintext using a DEK.
func EncryptEntry(dek []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := GenerateRandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ct...), nil
}

// DecryptEntry decrypts ciphertext using a DEK.
func DecryptEntry(dek []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce := data[:ns]
	ct := data[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

// GenerateSecurePassword creates a cryptographically secure random password.
// Default length = 16, includes uppercase, lowercase, digits, symbols.
func GenerateSecurePassword(length int) (string, error) {
	const (
		lower   = "abcdefghijklmnopqrstuvwxyz"
		upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits  = "0123456789"
		symbols = "!@#$%^&*()-_=+[]{}<>?/|~"
		all     = lower + upper + digits + symbols
	)

	if length < 12 {
		return "", fmt.Errorf("password length must be >= 12")
	}

	// Ensure at least one from each category
	categories := []string{lower, upper, digits, symbols}
	password := make([]byte, length)

	// Fill first 4 chars with guaranteed diversity
	for i, cat := range categories {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(cat))))
		if err != nil {
			return "", err
		}
		password[i] = cat[idx.Int64()]
	}

	// Fill the rest randomly
	for i := 4; i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(all))))
		if err != nil {
			return "", err
		}
		password[i] = all[idx.Int64()]
	}

	// Shuffle to avoid predictable start pattern
	for i := range password {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(password))))
		if err != nil {
			return "", err
		}
		password[i], password[j.Int64()] = password[j.Int64()], password[i]
	}

	return string(password), nil
}
