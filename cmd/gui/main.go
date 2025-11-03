package main

import (
	"Crypto-Project/internal/crypto"
	"Crypto-Project/internal/vault"
	"encoding/base64"
	"fmt"
	"image/color"
	"strings"
	"sort"
	"time"
	"unicode"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// Global settings variables (can be changed in the Settings window)
var (
	vaultFile          = "vault.json"
	clipboardTimeout   = 30 * time.Second 
	autoLockTimeout    = 1 * time.Minute  
	passwordLength     = 16 // Default generated password length
)

var (
	currentApp         fyne.App
	vaultTimer         *time.Timer
	currentVaultWindow fyne.Window
	openVaultWindows   []fyne.Window
	loginMessage       string
	loggingOut         bool = false
)

// ------------------- CUSTOM WIDGET FOR FASTER TOGGLE (REVISED) -------------------

// TappableText is a custom widget using canvas.Text for size control and tap behavior.
type TappableText struct {
	widget.BaseWidget
	text     *canvas.Text
	OnTapped func() // Function to execute when the text is tapped
}

// Extend the base widget to create a new custom TappableText
func NewTappableText(text string, tapped func(), size float32) *TappableText {
	t := &TappableText{
		text: canvas.NewText(text, theme.ForegroundColor()),
		OnTapped: tapped,
	}
	t.text.TextSize = size // Set the size here!
	t.text.Alignment = fyne.TextAlignLeading
	t.ExtendBaseWidget(t)
	return t
}

func (t *TappableText) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(t.text)
}

func (t *TappableText) MinSize() fyne.Size {
	return t.text.MinSize()
}

func (t *TappableText) SetText(text string) {
	t.text.Text = text
	t.text.Refresh()
	t.Refresh()
}

func (t *TappableText) SetBold(b bool) {
	if b {
		t.text.TextStyle.Bold = true
	} else {
		t.text.TextStyle.Bold = false
	}
	t.text.Refresh()
}

// Tapped implements the fyne.Tappable interface
func (t *TappableText) Tapped(*fyne.PointEvent) {
	if t.OnTapped != nil {
		t.OnTapped()
	}
}

// TappedSecondary implements the fyne.Tappable interface
func (t *TappableText) TappedSecondary(*fyne.PointEvent) {}

// ------------------- CUSTOM THEME FIX (FYNE ERROR) -------------------

// MyTheme defines a custom Fyne theme to fix the input background color.
type MyTheme struct {
	fyne.Theme 
}

func (m *MyTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	// CRITICAL FIX: Intercept the color requested for the Entry field background (fixes grey box).
	if name == theme.ColorNameInputBackground {
		return theme.DefaultTheme().Color(theme.ColorNameBackground, variant)
	}
	return theme.DefaultTheme().Color(name, variant)
}

func (m *MyTheme) Font(name fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(name)
}

func (m *MyTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (m *MyTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name) // ⭐️ REVERTED: Using the system default size for all general elements.
}

func NewMyTheme() fyne.Theme {
	return &MyTheme{theme.DefaultTheme()} 
}

// ------------------- MAIN -------------------

func main() {
	a := app.New()
	currentApp = a
	a.Settings().SetTheme(NewMyTheme()) 

	// Start with the intro window
	showIntroWindow(a)
	a.Run()
}

// ------------------- INTRO WINDOW -------------------

func showIntroWindow(a fyne.App) {
	w := a.NewWindow("Loading...")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(400, 300))
	w.CenterOnScreen() // <-- Centers the window
	w.SetPadded(false) // No padding for a centered feel
	
	welcome := widget.NewLabel("Welcome to Password Manager")
	welcome.TextStyle.Bold = true
	welcome.TextStyle.TabWidth = 50 // Ensures it appears centered better
	welcome.Alignment = fyne.TextAlignCenter
	
	// Percentage progress bar
	progress := widget.NewProgressBar()
	progress.SetValue(0.0)
	
	content := container.NewCenter(container.NewVBox(
		welcome,
		widget.NewSeparator(),
		widget.NewLabel("Simulating Vault Check..."),
		progress,
	))
	
	w.SetContent(content)
	w.Show()
	
	// Simulate the loading time and update the progress bar
	go func() {
		// Simulating a 1.5 second loading period
		totalSteps := 15
		for i := 1; i <= totalSteps; i++ {
			time.Sleep(100 * time.Millisecond) // 100ms per step
			fyne.Do(func() {
				value := float64(i) / float64(totalSteps)
				progress.SetValue(value)
			})
		}
		
		// When loading is complete, close the intro window and show the next
		fyne.Do(func() {
			w.Close()
			if vault.Exists(vaultFile) {
				showLoginWindow(a)
			} else {
				showSetupMasterPasswordWindow(a)
			}
		})
	}()
}


// ------------------- UTILS -------------------

func resetLockTimer() {
	if vaultTimer != nil {
		vaultTimer.Stop()
	}
	vaultTimer = time.AfterFunc(autoLockTimeout, func() { 
		fyne.Do(func() {
			for _, w := range openVaultWindows {
				w.Close()
			}
			openVaultWindows = nil
			currentVaultWindow = nil
			loginMessage = "You were logged out due to inactivity."
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
				status.SetText("Clipboard cleared.")
			} else {
				status.SetText("Clipboard changed.")
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

func initVaultSetup(password string) error {
	vaultSalt, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return err
	}
	vaultDEK, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return err
	}
	kek := crypto.DeriveKEK([]byte(password), vaultSalt)
	wrappedDEK, err := crypto.WrapKey(kek, vaultDEK)
	if err != nil {
		return err
	}
	return vault.SaveVault(vaultFile, []vault.Entry{}, vaultSalt, wrappedDEK)
}

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
		return "Decent 👍", normalized
	default:
		return "Very Weak 😞", normalized
	}
}

// ------------------- LOGIN WINDOW -------------------

func showLoginWindow(a fyne.App) {
	w := a.NewWindow("Crypto Vault Login")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(500, 500))
	w.CenterOnScreen() // <-- Centers the window

	w.SetOnClosed(func() { a.Quit() })

	title := widget.NewLabel("Login to Your Vault")
	title.TextStyle.Bold = true

	passEntry := widget.NewEntry()
	passEntry.Password = true
	passEntry.SetPlaceHolder("Enter Your Master Password")

	msg := widget.NewLabel(loginMessage)
	msg.Wrapping = fyne.TextWrapWord
	loginMessage = ""

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
				msg.SetText("Password too weak.")
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
			msg.SetText("Failed loading vault.")
			return
		}

		salt, _ := base64.StdEncoding.DecodeString(v.Salt)
		kek := crypto.DeriveKEK(password, salt)
		wrappedDEK, _ := base64.StdEncoding.DecodeString(v.WrappedDEK)
		dek, err := crypto.UnwrapKey(kek, wrappedDEK)
		if err != nil {
			msg.SetText("Wrong password.")
			return
		}

		msg.SetText("Vault unlocked ✅")
		w.Hide()
		showVaultWindow(a, v, dek)
	})

	form := container.NewVBox(title, passEntry, loginBtn, msg)
	w.SetContent(container.NewPadded(form))
	w.Show()
}

func showSetupMasterPasswordWindow(a fyne.App) {
	w := a.NewWindow("Set Your Master Password")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(500, 500))
	w.CenterOnScreen() // <-- Centers the window

	title := widget.NewLabel("Create Master Password")
	title.TextStyle.Bold = true

	pw := widget.NewEntry()
	pw.Password = true
	pw.SetPlaceHolder("Enter Your Master Password")

	confirm := widget.NewEntry()
	confirm.Password = true
	confirm.SetPlaceHolder("Confirm Master Password")

	msg := widget.NewLabel("")
	reqLabel := widget.NewLabel("Password requirements:\n• At least 8 characters\n• Uppercase and lowercase\n• Numbers\n• Symbols")
	reqLabel.Wrapping = fyne.TextWrapWord
	reqLabel.Alignment = fyne.TextAlignCenter

	strengthLabel := widget.NewLabel("Strength:")
	indicatorText := widget.NewLabel("")
	indicatorBar := widget.NewProgressBar()

	updateStrength := func(p string) {
		text, score := scorePassword(p)
		indicatorText.SetText(text)
		indicatorBar.SetValue(score)
	}
	pw.OnChanged = func(s string) { updateStrength(s) }

	saveBtn := widget.NewButton("Set Password", func() {
		password := strings.TrimSpace(pw.Text)
		if password == "" || confirm.Text == "" {
			msg.SetText("Fill all fields.")
			return
		}
		if password != confirm.Text {
			msg.SetText("Passwords do not match.")
			return
		}

		_, score := scorePassword(password)
		if score < 0.8 {
			msg.SetText("Password too weak.")
			return
		}

		salt, _ := crypto.GenerateRandomBytes(16)
		kek := crypto.DeriveKEK([]byte(password), salt)
		dek, _ := crypto.GenerateRandomBytes(32)
		wrapped, _ := crypto.WrapKey(kek, dek)

		v := &vault.Vault{
			Salt:       base64.StdEncoding.EncodeToString(salt),
			WrappedDEK: base64.StdEncoding.EncodeToString(wrapped),
			Entries:    []vault.Entry{},
		}
		v.Save(vaultFile)

		w.Close()
		showLoginWindow(a)
	})

	w.SetContent(container.NewVBox(
		title, pw, confirm, reqLabel,
		container.NewHBox(strengthLabel, container.NewVBox(indicatorBar, indicatorText)),
		saveBtn, msg,
	))
	w.Show()
}

// ------------------- UTILS: SETTINGS WINDOW -------------------

func showSettingsWindow(a fyne.App, refreshTimer func()) {
	resetLockTimer()
	w := a.NewWindow("Settings")
	openVaultWindows = append(openVaultWindows, w)
	w.SetOnClosed(func() { removeWindowFromSlice(w) })
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(500, 400))
	w.CenterOnScreen() // <-- Centers the window

	// --- 1. Clipboard Timeout Setting ---
	clipboardOptions := []string{"30 Seconds", "1 Minute", "3 Minutes"}
	clipboardSelect := widget.NewSelect(clipboardOptions, func(s string) {
		switch s {
		case "30 Seconds":
			clipboardTimeout = 30 * time.Second
		case "1 Minute":
			clipboardTimeout = 1 * time.Minute
		case "3 Minutes":
			clipboardTimeout = 3 * time.Minute
		}
	})

	// Set initial value based on the current global variable
	switch clipboardTimeout {
	case 30 * time.Second:
		clipboardSelect.SetSelected("30 Seconds")
	case 1 * time.Minute:
		clipboardSelect.SetSelected("1 Minute")
	case 3 * time.Minute:
		clipboardSelect.SetSelected("3 Minutes")
	default:
		clipboardSelect.SetSelected("30 Seconds") // Fallback
	}

	// --- 2. Auto-Logout Timeout Setting ---
	logoutOptions := []string{"1 Minute", "3 Minutes", "5 Minutes"}
	logoutSelect := widget.NewSelect(logoutOptions, func(s string) {
		switch s {
		case "1 Minute":
			autoLockTimeout = 1 * time.Minute
		case "3 Minutes":
			autoLockTimeout = 3 * time.Minute
		case "5 Minutes":
			autoLockTimeout = 5 * time.Minute
		}
		refreshTimer() // immediately update the running lock timer
	})

	// Set initial value
	switch autoLockTimeout {
	case 1 * time.Minute:
		logoutSelect.SetSelected("1 Minute")
	case 3 * time.Minute:
		logoutSelect.SetSelected("3 Minutes")
	case 5 * time.Minute:
		logoutSelect.SetSelected("5 Minutes")
	default:
		logoutSelect.SetSelected("1 Minute") // Fallback
	}
	
	// --- 3. Password Generation Length ---
	lengthOptions := []string{"12 Characters", "16 Characters", "24 Characters", "32 Characters"}
	
	lengthSelect := widget.NewSelect(lengthOptions, func(s string) {
		switch s {
		case "12 Characters":
			passwordLength = 12
		case "16 Characters":
			passwordLength = 16
		case "24 Characters":
			passwordLength = 24
		case "32 Characters":
			passwordLength = 32
		}
	})

	// Set initial value
	lengthSelect.SetSelected(fmt.Sprintf("%d Characters", passwordLength))
	if lengthSelect.Selected == "" {
		lengthSelect.SetSelected("16 Characters") // Fallback
	}
	

	content := container.NewVBox(
		widget.NewLabel("🔐 Security Settings"),
		widget.NewSeparator(),
		
		widget.NewLabel("Auto-Clear Clipboard Timeout:"),
		clipboardSelect,
		widget.NewSeparator(),

		widget.NewLabel("Auto-Logout Inactivity Timeout:"),
		logoutSelect,
		widget.NewSeparator(),

		widget.NewLabel("Default Password Generation Length:"),
		lengthSelect,
		
		widget.NewSeparator(),
		widget.NewButton("Close", func() { w.Close() }),
	)

	w.SetContent(container.NewPadded(content))
	w.Show()
}

// ------------------- UTILS: ADD ENTRY WINDOW -------------------

func showAddEntryWindow(a fyne.App, v *vault.Vault, dek []byte, list *widget.List, status *widget.Label, filterEntries func(string)) {
	resetLockTimer()

	w := a.NewWindow("Add Entry")
	openVaultWindows = append(openVaultWindows, w)
	w.SetOnClosed(func() { removeWindowFromSlice(w) })
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(450, 500))
	w.CenterOnScreen() // <-- Centers the window

	service := widget.NewEntry()
	service.SetPlaceHolder("Service (e.g. Gmail)")
	service.OnChanged = func(s string) { resetLockTimer() }

	username := widget.NewEntry()
	username.SetPlaceHolder("Username/email")
	username.OnChanged = func(s string) { resetLockTimer() }

	pw := widget.NewEntry()
	pw.Password = true
	pw.SetPlaceHolder("Account password")

	generatorBtn := widget.NewButton("Generate", func() {
		resetLockTimer()
		// Uses global passwordLength variable
		pass, err := crypto.GenerateSecurePassword(passwordLength) 
		if err != nil {
			status.SetText("Failed to generate")
			return
		}
		pw.SetText(pass)
	})
	generatorBtn.Importance = widget.LowImportance

	passwordInputRow := container.NewBorder(nil, nil, nil, generatorBtn, pw)

	strengthLabel := widget.NewLabel("Strength:")
	strengthLabel.TextStyle.Bold = true
	indicatorText := widget.NewLabel("")
	indicatorText.TextStyle.Bold = true
	indicatorBar := widget.NewProgressBar()

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

	notes := widget.NewMultiLineEntry()
	notes.SetPlaceHolder("Notes (optional)")
	notes.Wrapping = fyne.TextWrapWord
	notes.OnChanged = func(s string) { resetLockTimer() }

	save := widget.NewButton("Save", func() {
		resetLockTimer()
		if service.Text == "" || username.Text == "" || pw.Text == "" {
			status.SetText("Fill all fields")
			return
		}

		if err := v.AddEntry(service.Text, username.Text, pw.Text, notes.Text, dek); err != nil { 
			status.SetText("Error adding entry")
			return
		}

		v.Save(vaultFile)
		filterEntries("")
		list.Refresh()
		status.SetText("Entry added ✅")
		w.Close()
	})

	content := container.NewVBox(
		widget.NewLabel("Add New Entry"),
		container.NewPadded(service),
		container.NewPadded(username),
		passwordInputRow,
		container.NewHBox(strengthLabel, container.NewVBox(indicatorBar, indicatorText)),
		widget.NewLabel("Notes:"),
		notes,
		save,
	)

	w.SetContent(container.NewPadded(content))
	w.Show()
}


// ------------------- UTILS: EDIT ENTRY WINDOW -------------------

func showEditEntryWindow(a fyne.App, v *vault.Vault, dek []byte, index int, refreshList func(), status *widget.Label) {
	resetLockTimer()

	entry := v.Entries[index]

	w := a.NewWindow("Edit Entry")
	openVaultWindows = append(openVaultWindows, w)
	w.SetOnClosed(func() { removeWindowFromSlice(w) })
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(450, 550))
	w.CenterOnScreen() // <-- Centers the window

	w.SetCloseIntercept(func() { removeWindowFromSlice(w); w.Close() })

	// Service
	service := widget.NewEntry()
	service.SetText(decryptEntry(dek, entry.Service))
	service.SetPlaceHolder("Service (e.g., Gmail)")
	service.OnChanged = func(s string) { resetLockTimer() }

	// Username
	username := widget.NewEntry()
	username.SetText(decryptEntry(dek, entry.Username))
	username.SetPlaceHolder("Username/email")
	username.OnChanged = func(s string) { resetLockTimer() }

	// Password with eye toggle and generate button
	pw := widget.NewEntry()
	pw.SetText(decryptEntry(dek, entry.Password))
	pw.Password = true
	pw.OnChanged = func(s string) { resetLockTimer() }

	var toggleButton *widget.Button
	toggleFunc := func() {
		resetLockTimer()
		pw.Password = !pw.Password
		if pw.Password {
			toggleButton.SetIcon(theme.VisibilityIcon())
		} else {
			toggleButton.SetIcon(theme.VisibilityOffIcon())
		}
		pw.Refresh()
	}
	toggleButton = widget.NewButtonWithIcon("", theme.VisibilityIcon(), toggleFunc)

	generateBtn := widget.NewButton("Generate", func() {
		resetLockTimer()
		// Uses global passwordLength variable
		pass, err := crypto.GenerateSecurePassword(passwordLength) 
		if err != nil {
			status.SetText("Failed to generate password")
			return
		}
		pw.SetText(pass)
	})
	generateBtn.Importance = widget.LowImportance

	passwordRow := container.NewBorder(nil, nil, toggleButton, generateBtn, pw)

	// Notes (editable in edit window)
	notesBox := widget.NewMultiLineEntry()
	notesBox.SetText(decryptEntry(dek, entry.Notes))
	notesBox.Wrapping = fyne.TextWrapWord
	notesBox.OnChanged = func(s string) { resetLockTimer() }

	// Save button
	saveBtn := widget.NewButton("Save Changes", func() {
		resetLockTimer()
		if service.Text == "" || username.Text == "" || pw.Text == "" {
			status.SetText("Fill all fields")
			return
		}

		// encrypt updated fields
		newService, _ := crypto.EncryptEntry(dek, []byte(service.Text))
		newUsername, _ := crypto.EncryptEntry(dek, []byte(username.Text))
		newPassword, _ := crypto.EncryptEntry(dek, []byte(pw.Text))
		newNotes, _ := crypto.EncryptEntry(dek, []byte(notesBox.Text))

		v.Entries[index].Service = base64.StdEncoding.EncodeToString(newService)
		v.Entries[index].Username = base64.StdEncoding.EncodeToString(newUsername)
		v.Entries[index].Password = base64.StdEncoding.EncodeToString(newPassword)
		v.Entries[index].Notes = base64.StdEncoding.EncodeToString(newNotes)

		v.Save(vaultFile)
		refreshList()
		status.SetText("Entry updated ✅")
		w.Close()
	})

	content := container.NewVBox(
		widget.NewLabel("Service:"),
		service,
		widget.NewLabel("Username:"),
		username,
		widget.NewLabel("Password:"),
		passwordRow,
		widget.NewLabel("Notes:"),
		notesBox,
		saveBtn,
	)

	w.SetContent(container.NewPadded(content))
	w.Show()
}


	// ------------------- VAULT WINDOW -------------------

func showVaultWindow(a fyne.App, v *vault.Vault, dek []byte) {
	w := a.NewWindow("Crypto Vault")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(550, 500))
	w.CenterOnScreen() 

	currentVaultWindow = w
	openVaultWindows = append(openVaultWindows, w)

	w.SetOnClosed(func() {
		if vaultTimer != nil {
			vaultTimer.Stop()
		}
		currentVaultWindow = nil
		for _, win := range openVaultWindows {
			if win != w {
				win.Close()
			}
		}
		openVaultWindows = nil
	})

	resetLockTimer()

	var filteredEntries []vault.Entry
	selectedIndex := -1 // Global variable for selection state
	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Search...")
	status := widget.NewLabel("Vault unlocked.")

	var entriesList *widget.List

	filterEntries := func(query string) {
		query = strings.ToLower(query)
		filteredEntries = nil
		for i := range v.Entries {
			// Decrypt and normalize the fields we want to search in
			serviceStr := strings.ToLower(decryptEntry(dek, v.Entries[i].Service))
			notesStr := strings.ToLower(decryptEntry(dek, v.Entries[i].Notes))
            
			// Check if the query is empty or matches the service or notes
			if query == "" || strings.Contains(serviceStr, query) || strings.Contains(notesStr, query) {
				filteredEntries = append(filteredEntries, v.Entries[i])
			}
		}
        
		// ⭐️ ALPHABETICAL SORTING 
		sort.Slice(filteredEntries, func(i, j int) bool {
			serviceA := decryptEntry(dek, filteredEntries[i].Service)
			serviceB := decryptEntry(dek, filteredEntries[j].Service)
			return strings.ToLower(serviceA) < strings.ToLower(serviceB)
		})
        
		if entriesList != nil {
			entriesList.Refresh()
			selectedIndex = -1
		}
	}
	filterEntries("")

	entriesList = widget.NewList(
		func() int { return len(filteredEntries) },
		func() fyne.CanvasObject { 
			tappableText := NewTappableText("", func() {}, theme.TextSize()) 
			
			// ⭐️ WRAPPED IN PADDING TO INCREASE ROW HEIGHT ⭐️
			return container.NewPadded(tappableText)
		},
		func(i int, o fyne.CanvasObject) {
			// ⭐️ ACCESS INNER OBJECT FROM PADDED CONTAINER ⭐️
			paddedContainer := o.(*fyne.Container)
			tappableText := paddedContainer.Objects[0].(*TappableText) 
			
			// Set the left-aligned service name
			tappableText.SetText(decryptEntry(dek, filteredEntries[i].Service))
			
			// Set the Tapped action to implement the toggle logic
			tappableText.OnTapped = func() {
				resetLockTimer()
				
				if selectedIndex == i {
					entriesList.Unselect(i)
					status.SetText("Entry deselected.")
				} else {
					entriesList.Select(i)
				}
			}

			// Manually change the style to reflect selection state
			if selectedIndex == i {
				tappableText.SetBold(true)
			} else {
				tappableText.SetBold(false)
			}
			tappableText.Refresh()
		},
	)
    
	// Standard selection handler (fires when a *new* item is selected via click or programmatically)
	entriesList.OnSelected = func(id widget.ListItemID) {
		resetLockTimer()
		selectedIndex = int(id)
		status.SetText("Entry selected.")
		entriesList.Refresh() // Force refresh to update the visual state of the selected item
	}
    
	// Standard unselection handler (fires when unselect is called)
	entriesList.OnUnselected = func(id widget.ListItemID) {
		resetLockTimer()
		if selectedIndex == int(id) {
			selectedIndex = -1
		}
		status.SetText("Entry deselected.")
		entriesList.Refresh() // Force refresh to update the visual state of the deselected item
	}

	searchEntry.OnChanged = func(s string) { resetLockTimer(); filterEntries(s) }


	// ---------------- TOP BUTTONS ----------------
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
		notes := decryptEntry(dek, e.Notes)

		win := a.NewWindow("Entry Details: " + service)
		openVaultWindows = append(openVaultWindows, win)
		win.SetOnClosed(func() { removeWindowFromSlice(win) })
		win.SetFixedSize(true)
		win.Resize(fyne.NewSize(500, 350))
		win.CenterOnScreen() // <-- Centers the view window

		// Password Row
		passwordEntry := widget.NewEntry()
		passwordEntry.SetText(pass)
		passwordEntry.Password = true
		passwordEntry.Disable() 

		var toggleButton *widget.Button 
		toggleButton = widget.NewButtonWithIcon("", theme.VisibilityIcon(), func() {
			resetLockTimer()
			passwordEntry.Password = !passwordEntry.Password
			if passwordEntry.Password {
				toggleButton.SetIcon(theme.VisibilityIcon())
			} else {
				toggleButton.SetIcon(theme.VisibilityOffIcon())
			}
			passwordEntry.Refresh()
		})

		passwordRow := container.NewBorder(
			nil, nil,
			widget.NewLabel("Password:"),
			toggleButton,
			passwordEntry,
		)

		// Notes
		notesBox := widget.NewMultiLineEntry()
		notesBox.SetText(notes)
		notesBox.Disable() 

		// Copy Button
		copyButton := widget.NewButton("📋 Copy Password (Auto-Clear)", func() {
			resetLockTimer()
			copyToClipboard(win.Clipboard(), pass, status)
		})

		// Edit Button
		editButton := widget.NewButtonWithIcon(" Edit", theme.DocumentCreateIcon(), func() {
			resetLockTimer()
			win.Close() // close view window

			// find actual index in v.Entries
			masterIndex := -1
			for i, entry := range v.Entries {
				if entry.Service == filteredEntries[selectedIndex].Service &&
					entry.Username == filteredEntries[selectedIndex].Username {
					masterIndex = i
					break
				}
			}
			if masterIndex == -1 {
				status.SetText("Failed to locate entry")
				return
			}

			// open edit window
			showEditEntryWindow(a, v, dek, masterIndex, func() {
				filterEntries(searchEntry.Text) // rebuild filteredEntries
				entriesList.Refresh() 		 // refresh UI
			}, status)

		})

		closeButton := widget.NewButton("Close", func() { win.Close() })

		win.SetContent(container.NewVBox(
			widget.NewLabel("Service: "+service),
			widget.NewLabel("Username: "+user),
			widget.NewSeparator(),
			passwordRow,
			container.NewHBox(editButton),
			widget.NewLabel("Notes:"),
			notesBox,
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
			status.SetText("Entry not found.")
		}
	})

	settingsBtn := widget.NewButtonWithIcon("Settings", theme.SettingsIcon(), func() {
		showSettingsWindow(a, resetLockTimer)
	})

	logoutBtn := widget.NewButton("🚪 Logout", func() {
		if vaultTimer != nil {
			vaultTimer.Stop()
		}
		currentVaultWindow = nil
		for _, w := range openVaultWindows {
			w.Close()
		}
		openVaultWindows = nil

		loginMessage = "You logged out."
		showLoginWindow(a)
	})
    
	exitBtn := widget.NewButtonWithIcon("Exit", theme.ContentClearIcon(), func() {
		a.Quit() // Completely closes the Fyne application
	})

	topButtons := container.NewHBox(addBtn, viewBtn, deleteBtn, settingsBtn, logoutBtn, exitBtn)
	content := container.NewBorder(
		container.NewVBox(searchEntry, container.NewPadded(topButtons)),
		status, nil, nil, entriesList,
	)
	w.SetContent(content)
	w.Show()
}
	
