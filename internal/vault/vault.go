package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"

	"Crypto-Project/internal/crypto"
)

// Represents a single vault entry (all fields encrypted except timestamps)
type Entry struct {
	Service    string `json:"service"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Notes      string `json:"notes"`
	CreatedAt  int64  `json:"created_at"`  // time entry was first created
	ModifiedAt int64  `json:"modified_at"` // time entry was last modified
}

// Represents the whole encrypted vault file
type Vault struct {
	Salt       string  `json:"salt"`       // Base64 encoded salt
	WrappedDEK string  `json:"wrappedDEK"` // Base64 encrypted DEK
	Entries    []Entry `json:"entries"`
}

// Save vault state to disk
func (v *Vault) Save(filename string) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0600)
}

// Load vault from disk
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

// AddEntry encrypts and stores a new entry
func (v *Vault) AddEntry(service, username, password, notes string, dek []byte) error {
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
	encNotes, err := crypto.EncryptEntry(dek, []byte(notes))
	if err != nil {
		return err
	}

	entry := Entry{
		Service:    base64.StdEncoding.EncodeToString(encService),
		Username:   base64.StdEncoding.EncodeToString(encUsername),
		Password:   base64.StdEncoding.EncodeToString(encPassword),
		Notes:      base64.StdEncoding.EncodeToString(encNotes),
		CreatedAt:  time.Now().Unix(),
		ModifiedAt: time.Now().Unix(),
	}

	v.Entries = append(v.Entries, entry)
	return nil
}

// GetEntry decrypts one entry's data
func (v *Vault) GetEntry(index int, dek []byte) (service, username, password, notes string, err error) {
	if index < 0 || index >= len(v.Entries) {
		return "", "", "", "", errors.New("invalid entry index")
	}
	e := v.Entries[index]

	decService, _ := base64.StdEncoding.DecodeString(e.Service)
	decUsername, _ := base64.StdEncoding.DecodeString(e.Username)
	decPassword, _ := base64.StdEncoding.DecodeString(e.Password)
	decNotes, _ := base64.StdEncoding.DecodeString(e.Notes)

	serviceBytes, err := crypto.DecryptEntry(dek, decService)
	if err != nil {
		return "", "", "", "", err
	}

	usernameBytes, err := crypto.DecryptEntry(dek, decUsername)
	if err != nil {
		return "", "", "", "", err
	}

	passwordBytes, err := crypto.DecryptEntry(dek, decPassword)
	if err != nil {
		return "", "", "", "", err
	}

	notesBytes, err := crypto.DecryptEntry(dek, decNotes)
	if err != nil {
		return "", "", "", "", err
	}

	return string(serviceBytes), string(usernameBytes), string(passwordBytes), string(notesBytes), nil
}

// Check if vault file exists
func Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// Wrapper for UI code
func Load(filename string) (*Vault, error) {
	return LoadVault(filename)
}

// SaveVault initializes a brand new vault file (first-time setup)
func SaveVault(filename string, entries []Entry, salt []byte, wrappedDEK []byte) error {
	v := Vault{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		Entries:    entries,
	}
	return v.Save(filename)
}
