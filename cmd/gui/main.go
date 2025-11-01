package main

import (
	"encoding/base64"

	"Crypto-Project/internal/crypto"
	"Crypto-Project/internal/vault"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

const vaultFile = "vault.json"

func main() {
	a := app.New()
	showLoginWindow(a)
	a.Run()
}

// ---------------- LOGIN WINDOW ----------------

func showLoginWindow(a fyne.App) {
	w := a.NewWindow("Crypto Vault Login")

	title := widget.NewLabel("Master Password")
	title.TextStyle.Bold = true

	// Master password entry
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Enter master password")

	hint := widget.NewLabel("Use 12+ chars; include uppercase, numbers & symbols.")
	hint.Wrapping = fyne.TextWrapWord

	msg := widget.NewLabel("")

	loginBtn := widget.NewButton("Unlock Vault", func() {
		password := []byte(passEntry.Text)
		if len(password) == 0 {
			msg.SetText("Password required")
			return
		}

		// vault first time setup
		if !vault.Exists(vaultFile) {
			salt, _ := crypto.GenerateRandomBytes(16)
			kek := crypto.DeriveKEK(password, salt)
			dek, _ := crypto.GenerateRandomBytes(32)
			wrapped, _ := crypto.WrapKey(kek, dek)

			v := &vault.Vault{
				Salt:       base64.StdEncoding.EncodeToString(salt),
				WrappedDEK: base64.StdEncoding.EncodeToString(wrapped),
				Entries:    []vault.Entry{},
			}
			v.Save(vaultFile)

			w.Hide()
			showVaultWindow(a, v, dek)
			return
		}

		// unlock existing vault
		v, err := vault.Load(vaultFile)
		if err != nil {
			msg.SetText("Failed loading vault")
			return
		}

		salt, _ := base64.StdEncoding.DecodeString(v.Salt)
		kek := crypto.DeriveKEK(password, salt)
		wrappedDEK, _ := base64.StdEncoding.DecodeString(v.WrappedDEK)
		dek, err := crypto.UnwrapKey(kek, wrappedDEK)

		if err != nil {
			msg.SetText("Wrong password")
			return
		}

		msg.SetText("Vault unlocked ✅")
		w.Hide()
		showVaultWindow(a, v, dek)
	})

	form := container.NewVBox(
		title,
		passEntry, // just the entry
		hint,
		loginBtn,
		msg,
	)

	screen := container.NewCenter(form)

	w.SetContent(screen)
	w.Resize(fyne.NewSize(1000, 420)) // increase window width so entry is long
	w.Show()
}

// ---------------- VAULT WINDOW ----------------

func showVaultWindow(a fyne.App, v *vault.Vault, dek []byte) {
	w := a.NewWindow("Crypto Vault")

	status := widget.NewLabel("")
	selectedIndex := -1

	entriesList := widget.NewList(
		func() int { return len(v.Entries) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i int, o fyne.CanvasObject) {
			encServiceB, _ := base64.StdEncoding.DecodeString(v.Entries[i].Service)
			serviceBytes, _ := crypto.DecryptEntry(dek, encServiceB)
			o.(*widget.Label).SetText(string(serviceBytes))
		},
	)

	entriesList.OnSelected = func(id widget.ListItemID) {
		selectedIndex = int(id)
		status.SetText("")
	}
	entriesList.OnUnselected = func(id widget.ListItemID) {
		if selectedIndex == int(id) {
			selectedIndex = -1
		}
	}

	addBtn := widget.NewButton("➕ Add", func() {
		showAddEntryWindow(a, v, dek, entriesList, status)
	})

	viewBtn := widget.NewButton("🔍 View", func() {
		if selectedIndex < 0 {
			status.SetText("Select an entry first")
			return
		}
		e := v.Entries[selectedIndex]

		encUser, _ := base64.StdEncoding.DecodeString(e.Username)
		encPass, _ := base64.StdEncoding.DecodeString(e.Password)

		user, _ := crypto.DecryptEntry(dek, encUser)
		pass, _ := crypto.DecryptEntry(dek, encPass)

		win := a.NewWindow("Entry")
		win.SetContent(container.NewVBox(
			widget.NewLabel("Username: "+string(user)),
			widget.NewLabel("Password: "+string(pass)),
			widget.NewButton("Close", func() { win.Close() }),
		))
		win.Resize(fyne.NewSize(300, 130))
		win.Show()
	})

	deleteBtn := widget.NewButton("🗑 Delete", func() {
		if selectedIndex < 0 {
			status.SetText("Select entry")
			return
		}
		v.Entries = append(v.Entries[:selectedIndex], v.Entries[selectedIndex+1:]...)
		v.Save(vaultFile)
		entriesList.Refresh()
		selectedIndex = -1
		status.SetText("Entry deleted")
	})

	logoutBtn := widget.NewButton("🚪 Logout", func() {
		w.Close()
		showLoginWindow(a)
	})

	top := container.NewHBox(addBtn, viewBtn, deleteBtn, logoutBtn)

	w.SetContent(container.NewBorder(top, status, nil, nil, entriesList))
	w.Resize(fyne.NewSize(750, 520))
	w.Show()
}

// ---------------- ADD ENTRY WINDOW ----------------

func showAddEntryWindow(a fyne.App, v *vault.Vault, dek []byte, list *widget.List, status *widget.Label) {
	w := a.NewWindow("Add Entry")

	service := widget.NewEntry()
	service.SetPlaceHolder("Service (e.g. Gmail)")
	serviceBox := container.NewMax(service) // wide

	username := widget.NewEntry()
	username.SetPlaceHolder("Username/email")
	usernameBox := container.NewMax(username) // wide

	pw := widget.NewPasswordEntry()
	pw.SetPlaceHolder("Account password")
	pwBox := container.NewMax(pw) // wide

	save := widget.NewButton("Save", func() {
		if service.Text == "" || username.Text == "" || pw.Text == "" {
			status.SetText("Fill all fields")
			return
		}

		err := v.AddEntry(service.Text, username.Text, pw.Text, dek)
		if err != nil {
			status.SetText("Error adding entry")
			return
		}

		v.Save(vaultFile)
		list.Refresh()
		status.SetText("Entry added ✅")
		w.Close()
	})

	w.SetContent(container.NewVBox(
		widget.NewLabel("Add New Entry"),
		serviceBox,
		usernameBox,
		pwBox,
		save,
	))
	w.Resize(fyne.NewSize(900, 300)) // window width matches entry length
	w.Show()
}
