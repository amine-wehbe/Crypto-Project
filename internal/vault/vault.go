package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"

	"Crypto-Project/internal/crypto"
)

// Represents a single vault entry
type Entry struct {
	Service   string `json:"service"`  // Encrypted Base64
	Username  string `json:"username"` // Encrypted Base64
	Password  string `json:"password"` // Encrypted Base64
	CreatedAt int64  `json:"created_at"`
}

// Represents the whole vault
type Vault struct {
	Salt       string  `json:"salt"`       // Base64
	WrappedDEK string  `json:"wrappedDEK"` // Base64
	Entries    []Entry `json:"entries"`
}

// Save vault to a JSON file
func (v *Vault) Save(filename string) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0600) // strict permissions
}

// Load vault from a JSON file
func LoadVault(filename string) (*Vault, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// AddEntry encrypts and adds a new entry to the vault
func (v *Vault) AddEntry(service, username, password string, dek []byte) error {
	encService, err := crypto.EncryptEntry(dek, []byte(service))
	if err != nil {
		return err
	}
	encUsername, err := crypto.EncryptEntry(dek, []byte(username))
	if err != nil {
		return err
	}
	encPassword, err := crypto.EncryptEntry(dek, []byte(password))
	if err != nil {
		return err
	}

	entry := Entry{
		Service:   base64.StdEncoding.EncodeToString(encService),
		Username:  base64.StdEncoding.EncodeToString(encUsername),
		Password:  base64.StdEncoding.EncodeToString(encPassword),
		CreatedAt: time.Now().Unix(),
	}

	v.Entries = append(v.Entries, entry)
	return nil
}

// GetEntry decrypts and returns the fields of a vault entry
func (v *Vault) GetEntry(index int, dek []byte) (service, username, password string, err error) {
	if index < 0 || index >= len(v.Entries) {
		return "", "", "", errors.New("invalid entry index")
	}
	e := v.Entries[index]

	decService, err := base64.StdEncoding.DecodeString(e.Service)
	if err != nil {
		return "", "", "", err
	}
	decUsername, err := base64.StdEncoding.DecodeString(e.Username)
	if err != nil {
		return "", "", "", err
	}
	decPassword, err := base64.StdEncoding.DecodeString(e.Password)
	if err != nil {
		return "", "", "", err
	}

	serviceBytes, err := crypto.DecryptEntry(dek, decService)
	if err != nil {
		return "", "", "", err
	}
	usernameBytes, err := crypto.DecryptEntry(dek, decUsername)
	if err != nil {
		return "", "", "", err
	}
	passwordBytes, err := crypto.DecryptEntry(dek, decPassword)
	if err != nil {
		return "", "", "", err
	}

	return string(serviceBytes), string(usernameBytes), string(passwordBytes), nil
}

// Exists checks if a vault file exists
func Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// Load is a compatibility wrapper so UI code can call vault.Load()
func Load(filename string) (*Vault, error) {
	return LoadVault(filename)
}
