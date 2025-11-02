/*package main

import (
	"Crypto-Project/internal/crypto"
	"Crypto-Project/internal/vault"
	"encoding/base64"
	"fmt"
	"image/color"
	"strings"
	"time"
	"unicode"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const vaultFile = "vault.json"
const clipboardTimeout = 30 * time.Second
const autoLockTimeout = 1 * time.Minute

var currentApp fyne.App
var vaultTimer *time.Timer
var currentVaultWindow fyne.Window
var openVaultWindows []fyne.Window
var loginMessage string

func main() {
	a := app.New()
	currentApp = a
	showLoginWindow(a)
	a.Run()
}

// ------------------- UTILS -------------------

func resetLockTimer() {
	if vaultTimer != nil {
		vaultTimer.Stop()
	}

	vaultTimer = time.AfterFunc(autoLockTimeout, func() {
		fyne.Do(func() {
			// Close all vault windows
			for _, w := range openVaultWindows {
				w.Close()
			}
			openVaultWindows = nil
			currentVaultWindow = nil

			// Set the inactivity message
			loginMessage = "You were logged out due to inactivity."

			// Show login window safely
			showLoginWindow(currentApp)
		})
	})
}

func decryptEntry(dek []byte, entry string) string {
	enc, _ := base64.StdEncoding.DecodeString(entry)
	dec, _ := crypto.DecryptEntry(dek, enc)
	return string(dec)
}

func copyToClipboard(clipboard fyne.Clipboard, text string, status *widget.Label) {
	clipboard.SetContent(text)
	status.SetText(fmt.Sprintf("Password copied! Clearing in %s.", clipboardTimeout))
	status.Refresh()

	time.AfterFunc(clipboardTimeout, func() {
		fyne.Do(func() {
			if clipboard.Content() == text {
				clipboard.SetContent("")
				status.SetText("Clipboard cleared successfully.")
			} else {
				status.SetText("Clipboard content changed.")
			}
			status.Refresh()
		})
	})
}

func removeWindowFromSlice(win fyne.Window) {
	for i, w := range openVaultWindows {
		if w == win {
			openVaultWindows = append(openVaultWindows[:i], openVaultWindows[i+1:]...)
			break
		}
	}
}

// ------------------- PASSWORD STRENGTH -------------------

func scorePassword(password string) (string, float64) {
	length := len(password)
	score := 0.0
	if length >= 12 {
		score += 1.0
	} else if length >= 8 {
		score += 0.5
	}

	hasUpper, hasLower, hasDigit, hasSymbol := false, false, false, false
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	if hasUpper {
		score += 0.5
	}
	if hasLower {
		score += 0.5
	}
	if hasDigit {
		score += 1.0
	}
	if hasSymbol {
		score += 1.5
	}

	normalized := score / 4.5
	if normalized > 1.0 {
		normalized = 1.0
	}

	switch {
	case normalized >= 0.8 && length >= 12:
		return "Strong 💪", normalized
	case normalized >= 0.5:
		return "Good 👍", normalized
	default:
		return "Weak 😞", normalized
	}
}

// Custom Theme to color ProgressBar dynamically
type customTheme struct {
	base  fyne.Theme
	color color.Color
}

func (t *customTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if name == theme.ColorNameSuccess {
		return t.color
	}
	return t.base.Color(name, variant)
}
func (t *customTheme) Font(style fyne.TextStyle) fyne.Resource    { return t.base.Font(style) }
func (t *customTheme) Icon(name fyne.ThemeIconName) fyne.Resource { return t.base.Icon(name) }
func (t *customTheme) Size(name fyne.ThemeSizeName) float32       { return t.base.Size(name) }

// ------------------- LOGIN WINDOW -------------------

func showLoginWindow(a fyne.App) {
	w := a.NewWindow("Crypto Vault Login")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(500, 500))

	// Quit app if login window closed
	w.SetOnClosed(func() {
		a.Quit()
	})

	title := widget.NewLabel("Master Password")
	title.TextStyle.Bold = true

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Enter Master Password")

	hint := widget.NewLabel("Your password must be at least 12 characters long and contain uppercase letters, numbers, and symbols")
	hint.Wrapping = fyne.TextWrapWord

	msg := widget.NewLabel(loginMessage)
	msg.Wrapping = fyne.TextWrapWord
	loginMessage = "" // reset

	loginBtn := widget.NewButton("Unlock Vault", func() {
		resetLockTimer()

		passwordStr := strings.TrimSpace(passEntry.Text)
		password := []byte(passwordStr)

		if len(password) == 0 {
			msg.SetText("Password required")
			return
		}

		if !vault.Exists(vaultFile) {
			_, score := scorePassword(passwordStr)
			if score < 0.5 {
				msg.SetText("Master Password too weak. Choose 'Good' or 'Strong'.")
				return
			}

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

	form := container.NewVBox(title, passEntry, hint, loginBtn, msg)
	w.SetContent(container.NewPadded(form))
	w.Show()
}

// ------------------- VAULT WINDOW -------------------

func showVaultWindow(a fyne.App, v *vault.Vault, dek []byte) {
	w := a.NewWindow("Crypto Vault")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(750, 750))
	currentVaultWindow = w
	openVaultWindows = append(openVaultWindows, w)

	w.SetOnClosed(func() {
		if vaultTimer != nil {
			vaultTimer.Stop()
		}
		currentVaultWindow = nil
	})

	resetLockTimer()

	var filteredEntries []vault.Entry
	selectedIndex := -1
	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Search services...")

	var entriesList *widget.List

	filterEntries := func(query string) {
		query = strings.ToLower(query)
		filteredEntries = nil
		for i := range v.Entries {
			if strings.Contains(strings.ToLower(decryptEntry(dek, v.Entries[i].Service)), query) || query == "" {
				filteredEntries = append(filteredEntries, v.Entries[i])
			}
		}
		if entriesList != nil {
			entriesList.Refresh()
			selectedIndex = -1
		}
	}
	filterEntries("")

	entriesList = widget.NewList(
		func() int { return len(filteredEntries) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i int, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(decryptEntry(dek, filteredEntries[i].Service))
		},
	)

	searchEntry.OnChanged = func(s string) { resetLockTimer(); filterEntries(s) }

	status := widget.NewLabel("Vault unlocked.")
	mainClipboard := w.Clipboard()

	entriesList.OnSelected = func(id widget.ListItemID) { resetLockTimer(); selectedIndex = int(id); status.SetText("") }
	entriesList.OnUnselected = func(id widget.ListItemID) {
		resetLockTimer()
		if selectedIndex == int(id) {
			selectedIndex = -1
		}
	}

	addBtn := widget.NewButton("➕ Add", func() {
		resetLockTimer()
		showAddEntryWindow(a, v, dek, entriesList, status, filterEntries)
		filterEntries(searchEntry.Text)
	})

	viewBtn := widget.NewButton("🔍 View", func() {
		resetLockTimer()
		if selectedIndex < 0 {
			status.SetText("Select an entry first")
			return
		}
		e := filteredEntries[selectedIndex]
		user := decryptEntry(dek, e.Username)
		pass := decryptEntry(dek, e.Password)
		service := decryptEntry(dek, e.Service)

		win := a.NewWindow("Entry")
		openVaultWindows = append(openVaultWindows, win)
		win.SetOnClosed(func() { removeWindowFromSlice(win) })
		win.SetFixedSize(true)
		win.Resize(fyne.NewSize(450, 200))

		copyButton := widget.NewButton("📋 Copy Password (Auto-Clear)", func() {
			resetLockTimer()
			copyToClipboard(mainClipboard, pass, status)
		})

		win.SetContent(container.NewVBox(
			widget.NewLabel("Service: "+service),
			widget.NewSeparator(),
			widget.NewLabel("Username: "+user),
			copyButton,
			widget.NewButton("Close", func() { win.Close() }),
		))
		win.Show()
	})

	deleteBtn := widget.NewButton("🗑 Delete", func() {
		resetLockTimer()
		if selectedIndex < 0 {
			status.SetText("Select entry")
			return
		}
		entry := filteredEntries[selectedIndex]
		masterIndex := -1
		for i, e := range v.Entries {
			if e.Service == entry.Service && e.Username == entry.Username {
				masterIndex = i
				break
			}
		}
		if masterIndex != -1 {
			v.Entries = append(v.Entries[:masterIndex], v.Entries[masterIndex+1:]...)
			v.Save(vaultFile)
			filterEntries(searchEntry.Text)
			status.SetText("Entry deleted")
		} else {
			status.SetText("Error: Entry not found.")
		}
	})

	logoutBtn := widget.NewButton("🚪 Logout", func() {
		if vaultTimer != nil {
			vaultTimer.Stop()
		}
		currentVaultWindow = nil
		w.Close()
		loginMessage = ""
		showLoginWindow(a)
	})

	topButtons := container.NewHBox(addBtn, viewBtn, deleteBtn, logoutBtn)
	w.SetContent(container.NewBorder(container.NewVBox(searchEntry, container.NewPadded(topButtons)), status, nil, nil, entriesList))
	w.Show()
}

// ------------------- ADD ENTRY WINDOW -------------------

func showAddEntryWindow(a fyne.App, v *vault.Vault, dek []byte, list *widget.List, status *widget.Label, filterEntries func(string)) {
	resetLockTimer()

	w := a.NewWindow("Add Entry")
	openVaultWindows = append(openVaultWindows, w)
	w.SetOnClosed(func() { removeWindowFromSlice(w) })
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(450, 350))

	service := widget.NewEntry()
	service.SetPlaceHolder("Service (e.g. Gmail)")
	service.OnChanged = func(s string) { resetLockTimer() }
	username := widget.NewEntry()
	username.SetPlaceHolder("Username/email")
	username.OnChanged = func(s string) { resetLockTimer() }
	pw := widget.NewPasswordEntry()
	pw.SetPlaceHolder("Account password")
	pw.OnChanged = func(s string) { resetLockTimer() }

	strengthLabel := widget.NewLabel("Strength:")
	strengthLabel.TextStyle.Bold = true
	indicatorText := widget.NewLabel("")
	indicatorText.TextStyle.Bold = true
	indicatorBar := widget.NewProgressBar()
	indicatorBar.Min = 0.0
	indicatorBar.Max = 1.0

	updateIndicator := func(pwStr string) {
		text, score := scorePassword(pwStr)
		indicatorText.SetText(text)
		indicatorBar.SetValue(score)
	}
	updateIndicator(pw.Text)
	pw.OnChanged = updateIndicator

	save := widget.NewButton("Save", func() {
		resetLockTimer()
		if service.Text == "" || username.Text == "" || pw.Text == "" {
			status.SetText("Fill all fields")
			return
		}
		if err := v.AddEntry(service.Text, username.Text, pw.Text, dek); err != nil {
			status.SetText("Error adding entry")
			return
		}
		v.Save(vaultFile)
		filterEntries("")
		list.Refresh()
		status.SetText("Entry added ✅")
		w.Close()
	})

	w.SetContent(container.NewVBox(
		widget.NewLabel("Add New Entry"),
		container.NewPadded(service),
		container.NewPadded(username),
		container.NewPadded(pw),
		container.NewHBox(strengthLabel, container.NewVBox(indicatorBar, indicatorText)),
		save,
	))
	w.Show()
}
*/

package main

import (
	"Crypto-Project/internal/crypto"
	"Crypto-Project/internal/vault"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unicode"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const vaultFile = "vault.json"
const clipboardTimeout = 30 * time.Second
const autoLockTimeout = 1 * time.Minute

var currentApp fyne.App
var vaultTimer *time.Timer
var currentVaultWindow fyne.Window
var openVaultWindows []fyne.Window
var loginMessage string

func main() {
	a := app.New()
	currentApp = a
	showLoginWindow(a)
	a.Run()
}

// ------------------- UTILS -------------------

func resetLockTimer() {
	if vaultTimer != nil {
		vaultTimer.Stop()
	}

	vaultTimer = time.AfterFunc(autoLockTimeout, func() {
		fyne.Do(func() {
			// Close all vault windows
			for _, w := range openVaultWindows {
				w.Close()
			}
			openVaultWindows = nil
			currentVaultWindow = nil

			// Set the inactivity message
			loginMessage = "You were logged out due to inactivity."

			// Show login window safely
			showLoginWindow(currentApp)
		})
	})
}

func decryptEntry(dek []byte, entry string) string {
	enc, _ := base64.StdEncoding.DecodeString(entry)
	dec, _ := crypto.DecryptEntry(dek, enc)
	return string(dec)
}

func copyToClipboard(clipboard fyne.Clipboard, text string, status *widget.Label) {
	clipboard.SetContent(text)
	status.SetText(fmt.Sprintf("Password copied! Clearing in %s.", clipboardTimeout))
	status.Refresh()

	time.AfterFunc(clipboardTimeout, func() {
		fyne.Do(func() {
			if clipboard.Content() == text {
				clipboard.SetContent("")
				status.SetText("Clipboard cleared successfully.")
			} else {
				status.SetText("Clipboard content changed.")
			}
			status.Refresh()
		})
	})
}

func removeWindowFromSlice(win fyne.Window) {
	for i, w := range openVaultWindows {
		if w == win {
			openVaultWindows = append(openVaultWindows[:i], openVaultWindows[i+1:]...)
			break
		}
	}
}

// ------------------- PASSWORD STRENGTH -------------------

func scorePassword(password string) (string, float64) {
	length := len(password)
	score := 0.0
	if length >= 12 {
		score += 1.0
	} else if length >= 8 {
		score += 0.5
	}

	hasUpper, hasLower, hasDigit, hasSymbol := false, false, false, false
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	if hasUpper {
		score += 0.5
	}
	if hasLower {
		score += 0.5
	}
	if hasDigit {
		score += 1.0
	}
	if hasSymbol {
		score += 1.5
	}

	normalized := score / 4.5
	if normalized > 1.0 {
		normalized = 1.0
	}

	switch {
	case normalized >= 0.8 && length >= 12:
		return "Strong 💪", normalized
	case normalized >= 0.5:
		return "Good 👍", normalized
	default:
		return "Weak 😞", normalized
	}
}

// ------------------- LOGIN WINDOW -------------------

func showLoginWindow(a fyne.App) {
	a.Settings().SetTheme(theme.DefaultTheme())
    
	w := a.NewWindow("Crypto Vault Login")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(500, 500))

	w.SetOnClosed(func() {
		a.Quit()
	})

	title := widget.NewLabel("Master Password")
	title.TextStyle.Bold = true

	// 🌟 FIX: Use NewEntry and set Password=true 🌟
	passEntry := widget.NewEntry()
	passEntry.Password = true
	passEntry.SetPlaceHolder("Enter Master Password")

	hint := widget.NewLabel("Your password must be at least 12 characters long and contain uppercase letters, numbers, and symbols")
	hint.Wrapping = fyne.TextWrapWord

	msg := widget.NewLabel(loginMessage)
	msg.Wrapping = fyne.TextWrapWord
	loginMessage = "" // reset

	loginBtn := widget.NewButton("Unlock Vault", func() {
		resetLockTimer()

		passwordStr := strings.TrimSpace(passEntry.Text)
		password := []byte(passwordStr)

		if len(password) == 0 {
			msg.SetText("Password required")
			return
		}

		if !vault.Exists(vaultFile) {
			_, score := scorePassword(passwordStr)
			if score < 0.5 {
				msg.SetText("Master Password too weak. Choose 'Good' or 'Strong'.")
				return
			}
			
			salt, _ := crypto.GenerateRandomBytes(16)
			kek := crypto.DeriveKEK(password, salt)
			dek, _ := crypto.GenerateRandomBytes(32)
			wrapped, _ := crypto.WrapKey(kek, dek)

			v := &vault.Vault{
				Salt:  base64.StdEncoding.EncodeToString(salt),
				WrappedDEK: base64.StdEncoding.EncodeToString(wrapped),
				Entries: []vault.Entry{},
			}
			v.Save(vaultFile)

			w.Hide()
			showVaultWindow(a, v, dek)
			return
		}

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

	form := container.NewVBox(title, passEntry, hint, loginBtn, msg)
	w.SetContent(container.NewPadded(form))
	w.Show()
}

// ------------------- VAULT WINDOW -------------------

func showVaultWindow(a fyne.App, v *vault.Vault, dek []byte) {
	w := a.NewWindow("Crypto Vault")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(750, 750))
	currentVaultWindow = w
	openVaultWindows = append(openVaultWindows, w)

	w.SetOnClosed(func() {
		if vaultTimer != nil {
			vaultTimer.Stop()
		}
		currentVaultWindow = nil
		removeWindowFromSlice(w) 
	})

	resetLockTimer()

	var filteredEntries []vault.Entry
	selectedIndex := -1
	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Search services...")

	var entriesList *widget.List

	filterEntries := func(query string) {
		query = strings.ToLower(query)
		filteredEntries = nil
		for i := range v.Entries {
			if strings.Contains(strings.ToLower(decryptEntry(dek, v.Entries[i].Service)), query) || query == "" {
				filteredEntries = append(filteredEntries, v.Entries[i])
			}
		}
		if entriesList != nil {
			entriesList.Refresh()
			selectedIndex = -1
		}
	}
	filterEntries("")

	entriesList = widget.NewList(
		func() int { return len(filteredEntries) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i int, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(decryptEntry(dek, filteredEntries[i].Service))
		},
	)

	searchEntry.OnChanged = func(s string) { resetLockTimer(); filterEntries(s) }

	status := widget.NewLabel("Vault unlocked.")
	mainClipboard := w.Clipboard()

	entriesList.OnSelected = func(id widget.ListItemID) { resetLockTimer(); selectedIndex = int(id); status.SetText("") }
	entriesList.OnUnselected = func(id widget.ListItemID) {
		resetLockTimer()
		if selectedIndex == int(id) {
			selectedIndex = -1
		}
	}

	addBtn := widget.NewButton("➕ Add", func() {
		resetLockTimer()
		showAddEntryWindow(a, v, dek, entriesList, status, filterEntries)
		filterEntries(searchEntry.Text)
	})

	viewBtn := widget.NewButton("🔍 View", func() {
		resetLockTimer()
		if selectedIndex < 0 {
			status.SetText("Select an entry first")
			return
		}
		e := filteredEntries[selectedIndex]
		user := decryptEntry(dek, e.Username)
		pass := decryptEntry(dek, e.Password)
		service := decryptEntry(dek, e.Service)

		win := a.NewWindow("Entry Details: " + service)
		openVaultWindows = append(openVaultWindows, win)
		win.SetOnClosed(func() { removeWindowFromSlice(win) })
		win.SetFixedSize(true)
		win.Resize(fyne.NewSize(500, 200)) 

		// 🌟 FIX: Use widget.Entry and toggle its Password flag 🌟
		
		// 1. Initial masked password field (read-only)
		passwordEntry := widget.NewEntry()
		passwordEntry.SetText(pass)
		passwordEntry.Password = true // ⬅️ Set the mask
		passwordEntry.Disable() 

		// Container to hold the swappable field
		// In v1.x, we can directly manipulate the Password field of a single Entry
		
		// The eye button (declared before the toggle logic)
		var toggleButton *widget.Button
		
		// 2. Define the toggle logic (manipulates the single passwordEntry)
		toggleFunc := func() {
			resetLockTimer()
			
			// Toggle the Password field
			passwordEntry.Password = !passwordEntry.Password
			
			if passwordEntry.Password {
				toggleButton.SetIcon(theme.VisibilityIcon())
			} else {
				toggleButton.SetIcon(theme.VisibilityOffIcon())
			}
			passwordEntry.Refresh() // Crucial to redraw the widget
		}
		
		// 3. Create the button, which calls the toggle function
		toggleButton = widget.NewButtonWithIcon("", theme.VisibilityIcon(), toggleFunc)
		toggleButton.Importance = widget.LowImportance
		
		// Layout container for the password entry and the eye button
		passwordRow := container.NewBorder(
			nil,
			nil,
			widget.NewLabel("Password: "), // Label on the left
			toggleButton, // Button on the right
			passwordEntry, // The single Entry is placed here
		)
		
		copyButton := widget.NewButton("📋 Copy Password (Auto-Clear)", func() {
			resetLockTimer()
			copyToClipboard(mainClipboard, pass, status)
		})
		
		closeButton := widget.NewButton("Close", func() { win.Close() })

		win.SetContent(container.NewVBox(
			widget.NewLabel("Service: "+service),
			widget.NewLabel("Username: "+user),
			widget.NewSeparator(),
			passwordRow, // The secure password field with toggle
			copyButton,
			closeButton,
		))
		win.Show()
	})

	deleteBtn := widget.NewButton("🗑 Delete", func() {
		resetLockTimer()
		if selectedIndex < 0 {
			status.SetText("Select entry")
			return
		}
		entry := filteredEntries[selectedIndex]
		masterIndex := -1
		for i, e := range v.Entries {
			if e.Service == entry.Service && e.Username == entry.Username {
				masterIndex = i
				break
			}
		}
		if masterIndex != -1 {
			v.Entries = append(v.Entries[:masterIndex], v.Entries[masterIndex+1:]...)
			v.Save(vaultFile)
			filterEntries(searchEntry.Text)
			status.SetText("Entry deleted")
		} else {
			status.SetText("Error: Entry not found.")
		}
	})

	logoutBtn := widget.NewButton("🚪 Logout", func() {
		if vaultTimer != nil {
			vaultTimer.Stop()
		}
		currentVaultWindow = nil
		fyne.Do(func() { 
			for _, w := range openVaultWindows {
				w.Close()
			}
			openVaultWindows = nil
			w.Close()
			loginMessage = ""
			showLoginWindow(a)
		})
	})

	topButtons := container.NewHBox(addBtn, viewBtn, deleteBtn, logoutBtn)
	content := container.NewBorder(container.NewVBox(searchEntry, container.NewPadded(topButtons)), status, nil, nil, entriesList)
	w.SetContent(content)
	w.Show()
}



// ------------------- ADD ENTRY WINDOW -------------------

func showAddEntryWindow(a fyne.App, v *vault.Vault, dek []byte, list *widget.List, status *widget.Label, filterEntries func(string)) {
	resetLockTimer()

	w := a.NewWindow("Add Entry")
	openVaultWindows = append(openVaultWindows, w)
	w.SetOnClosed(func() { removeWindowFromSlice(w) })
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(450, 400)) 

	service := widget.NewEntry()
	service.SetPlaceHolder("Service (e.g. Gmail)")
	service.OnChanged = func(s string) { resetLockTimer() }

	username := widget.NewEntry()
	username.SetPlaceHolder("Username/email")
	username.OnChanged = func(s string) { resetLockTimer() }

	// Use NewEntry and set Password=true
	pw := widget.NewEntry()
	pw.Password = true
	pw.SetPlaceHolder("Account password")
	
	// Prepare for the Password Generator Button
	generatorBtn := widget.NewButton("Generate", func() {
		resetLockTimer()
		// TODO: Implement password generation logic
	})
	generatorBtn.Importance = widget.LowImportance

	
	passwordInputRow := container.NewBorder(
		nil, 
		nil, 
		nil, 
		generatorBtn, 
		pw, // The password entry
	)


	// Password strength indicators for new entry (kept)
	strengthLabel := widget.NewLabel("Strength:")
	strengthLabel.TextStyle.Bold = true
	indicatorText := widget.NewLabel("")
	indicatorText.TextStyle.Bold = true
	indicatorBar := widget.NewProgressBar()
	indicatorBar.Min = 0.0
	indicatorBar.Max = 1.0

	updateIndicator := func(pwStr string) {
		text, score := scorePassword(pwStr)
		indicatorText.SetText(text)
		indicatorBar.SetValue(score)
	}
	updateIndicator(pw.Text)
	
	pw.OnChanged = func(s string) { 
		resetLockTimer() 
		updateIndicator(s)
	}

	save := widget.NewButton("Save", func() {
		resetLockTimer()
		if service.Text == "" || username.Text == "" || pw.Text == "" {
			status.SetText("Fill all fields")
			return
		}

		if err := v.AddEntry(service.Text, username.Text, pw.Text, dek); err != nil { 
			status.SetText("Error adding entry")
			return
		}
		
		v.Save(vaultFile)
		filterEntries("")
		list.Refresh()
		status.SetText("Entry added ✅")
		w.Close()
	})

	// Wrap the core content in NewVBox
	content := container.NewVBox(
		widget.NewLabel("Add New Entry"),
		service,
		username,
		passwordInputRow, 
		container.NewHBox(strengthLabel, container.NewVBox(indicatorBar, indicatorText)),
		save,
	)

	// Wrap the VBox content in NewPadded to provide overall window margin
	w.SetContent(container.NewPadded(content))
	w.Show()
}
