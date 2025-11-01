package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"

	"Crypto-Project/internal/crypto"
	"Crypto-Project/internal/vault"
)

const vaultFile = "vault.json"

func main() {
	reader := bufio.NewReader(os.Stdin)

	var v *vault.Vault
	var dek []byte
	var salt []byte

	// Check if vault exists
	if _, err := os.Stat(vaultFile); os.IsNotExist(err) {
		fmt.Println("Vault not found. Creating new vault...")

		// Prompt for master password
		fmt.Print("Enter a master password: ")
		pass, _ := reader.ReadString('\n')
		pass = pass[:len(pass)-1] // remove newline

		// Generate salt
		salt, _ = crypto.GenerateRandomBytes(16)

		// Derive KEK
		kek := crypto.DeriveKEK([]byte(pass), salt)

		// Generate DEK
		dek, _ = crypto.GenerateRandomBytes(32)

		// Wrap DEK
		wrappedDEK, _ := crypto.WrapKey(kek, dek)

		// Initialize vault
		v = &vault.Vault{
			Salt:       base64.StdEncoding.EncodeToString(salt),
			WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
			Entries:    []vault.Entry{},
		}

		v.Save(vaultFile)
		fmt.Println("Vault created and saved!")

	} else {
		// Vault exists → load it
		vaultLoaded, err := vault.LoadVault(vaultFile)
		if err != nil {
			fmt.Println("Error loading vault:", err)
			return
		}
		v = vaultLoaded

		// Prompt for master password
		fmt.Print("Enter your master password: ")
		pass, _ := reader.ReadString('\n')
		pass = pass[:len(pass)-1]

		// Decode salt and wrappedDEK
		salt, _ = base64.StdEncoding.DecodeString(v.Salt)
		wrappedDEK, _ := base64.StdEncoding.DecodeString(v.WrappedDEK)

		// Derive KEK
		kek := crypto.DeriveKEK([]byte(pass), salt)

		// Unwrap DEK
		dekUnwrapped, err := crypto.UnwrapKey(kek, wrappedDEK)
		if err != nil {
			fmt.Println("Invalid master password or corrupted vault!")
			return
		}
		dek = dekUnwrapped
		fmt.Println("Vault unlocked!")
	}

	// Add a test entry
	fmt.Println("\nAdding test entry...")
	v.AddEntry("Example Service", "example@gmail.com", "ilovecats123", dek)
	v.Save(vaultFile)
	fmt.Println("Test entry added!")

	// List entries
	fmt.Println("\nVault Entries:")
	for i := range v.Entries {
		service, username, password, _ := v.GetEntry(i, dek)
		fmt.Printf("%d) Service: %s | Username: %s | Password: %s\n", i+1, service, username, password)
	}
}
