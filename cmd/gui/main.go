/*package main

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

*/


package main

import (
	"encoding/base64"
	"fmt"
	"image/color"
	"strings"
	"time"
	"unicode"

	"Crypto-Project/internal/crypto"
	"Crypto-Project/internal/vault"

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

func main() {
	a := app.New()
    currentApp = a 
	showLoginWindow(a)
	a.Run()
}

// FIX: Use fyne.Do() to ensure UI operations (close, show, set text) run on the main thread
func resetLockTimer() {
	if vaultTimer != nil {
		vaultTimer.Stop()
	}

	vaultTimer = time.AfterFunc(autoLockTimeout, func() {
		fyne.Do(func() {
			if currentVaultWindow != nil {
				
				if status, ok := currentVaultWindow.Content().(*fyne.Container).Objects[1].(*widget.Label); ok {
					status.SetText("Vault locked due to inactivity.")
				}

				currentVaultWindow.Close() 
				currentVaultWindow = nil
				
				showLoginWindow(currentApp)
			}
		}) 
	})
}

// scorePassword function remains unchanged
func scorePassword(password string) (string, float64) {
	length := len(password)
	score := 0.0
	if length >= 12 {
		score += 1.0
	} else if length >= 8 {
		score += 0.5
	}
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSymbol := false
	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUpper = true
		} else if unicode.IsLower(char) {
			hasLower = true
		} else if unicode.IsDigit(char) {
			hasDigit = true
		} else if unicode.IsPunct(char) || unicode.IsSymbol(char) {
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
	normalizedScore := score / 4.5
	if normalizedScore > 1.0 {
		normalizedScore = 1.0
	}
	var strengthText string
	if normalizedScore >= 0.8 && length >= 12 {
		strengthText = "Strong 💪"
	} else if normalizedScore >= 0.5 {
		strengthText = "Good 👍"
	} else {
		strengthText = "Weak 😞"
	}
	return strengthText, normalizedScore
}

// Custom Theme Structure to force color change on ProgressBar 
type customTheme struct {
	base fyne.Theme
	color color.Color
}

func (t *customTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if name == theme.ColorNameSuccess {
		return t.color
	}
	return t.base.Color(name, variant)
}

func (t *customTheme) Font(style fyne.TextStyle) fyne.Resource {
	return t.base.Font(style)
}

func (t *customTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return t.base.Icon(name)
}

func (t *customTheme) Size(name fyne.ThemeSizeName) float32 {
	return t.base.Size(name)
}

// ---------------- LOGIN WINDOW ----------------

func showLoginWindow(a fyne.App) {
	w := a.NewWindow("Crypto Vault Login")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(500, 500))

	title := widget.NewLabel("Master Password")
	title.TextStyle.Bold = true

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Enter Master Password")

    // 🌟 NEW WIDGETS FOR STRENGTH CHECK 🌟
	strengthLabel := widget.NewLabel("Strength:")
	strengthLabel.TextStyle.Bold = true

	indicatorText := widget.NewLabel("")
	indicatorText.TextStyle.Bold = true

	indicatorBar := widget.NewProgressBar()
	indicatorBar.Min = 0.0
	indicatorBar.Max = 1.0
    // ------------------------------------

	hint := widget.NewLabel("Your password must be at least 12 characters long and contain uppercase letters, numbers, and symbols")
	hint.Wrapping = fyne.TextWrapWord

	msg := widget.NewLabel("")

    // Helper function for theme changes
    progressTheme := func(c color.Color) fyne.Theme {
		return &customTheme{
			base: theme.DefaultTheme(),
			color: c,
		}
	}
    
    // Function to update the bar and text
    updateIndicator := func(s string) {
		text, score := scorePassword(s)
		
        var barColor color.Color
		if score < 0.33 {
			barColor = color.RGBA{R: 200, G: 0, B: 0, A: 255} // Red
		} else if score < 0.66 {
			barColor = color.RGBA{R: 255, G: 165, B: 0, A: 255} // Orange
		} else {
			barColor = color.RGBA{R: 0, G: 150, B: 0, A: 255} // Green
		}

        fyne.Do(func() {
            indicatorText.SetText(text)
            indicatorBar.SetValue(score)
            currentApp.Settings().SetTheme(progressTheme(barColor))

            indicatorText.Refresh()
            indicatorBar.Refresh()
        })
	}

    // Attach listener to password entry
    passEntry.OnChanged = updateIndicator

    // Initial call to set the default state
    updateIndicator(passEntry.Text)
    
    // Arrange strength check widgets
    indicatorTextBar := container.NewVBox(indicatorBar, container.NewHBox(indicatorText))
	indicatorBox := container.NewHBox(strengthLabel, indicatorTextBar)


	loginBtn := widget.NewButton("Unlock Vault", func() {
		passwordStr := strings.TrimSpace(passEntry.Text)
		password := []byte(passwordStr)

		if len(password) == 0 {
			msg.SetText("Password required")
            currentApp.Settings().SetTheme(theme.DefaultTheme())
			return
		}
        
        // 🌟 CHECK STRENGTH FOR NEW VAULT 🌟
		if !vault.Exists(vaultFile) {
            _, score := scorePassword(passwordStr)
            if score < 0.5 { 
                msg.SetText("Master Password is too weak. Please choose a 'Good' or 'Strong' one.")
                currentApp.Settings().SetTheme(theme.DefaultTheme())
                return
            }
            
            // Proceed with new vault creation (only runs if password is strong enough)
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
            
            currentApp.Settings().SetTheme(theme.DefaultTheme()) // Reset theme before closing
			w.Hide()
			showVaultWindow(a, v, dek)
			return
		}

        // Existing vault unlock logic
		v, err := vault.Load(vaultFile)
		if err != nil {
			msg.SetText("Failed loading vault")
            currentApp.Settings().SetTheme(theme.DefaultTheme())
			return
		}

		salt, _ := base64.StdEncoding.DecodeString(v.Salt)
		kek := crypto.DeriveKEK(password, salt)
		wrappedDEK, _ := base64.StdEncoding.DecodeString(v.WrappedDEK)
		dek, err := crypto.UnwrapKey(kek, wrappedDEK)

		if err != nil {
			msg.SetText("Wrong password")
            currentApp.Settings().SetTheme(theme.DefaultTheme())
			return
		}

		msg.SetText("Vault unlocked ✅")
        currentApp.Settings().SetTheme(theme.DefaultTheme()) // Reset theme before closing
		w.Hide()
		showVaultWindow(a, v, dek)
	})

	form := container.NewVBox(
		title,
		passEntry,
        indicatorBox, // 🌟 ADDED 🌟
		hint,
		loginBtn,
		msg,
	)

	screen := container.NewPadded(form)

	w.SetContent(screen)
	w.Show()
}

// ---------------- VAULT WINDOW ----------------

func showVaultWindow(a fyne.App, v *vault.Vault, dek []byte) {
	w := a.NewWindow("Crypto Vault")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(750, 750))
    currentVaultWindow = w 
    
	w.SetOnClosed(func() {
		if vaultTimer != nil {
            vaultTimer.Stop()
        }
		currentVaultWindow = nil
	})
    
    resetLockTimer() 

    // Attach timer reset to various window interaction events 
    w.Canvas().SetOnTypedKey(func(k *fyne.KeyEvent) {
        resetLockTimer()
    })
    w.Canvas().SetOnTypedRune(func(r rune) {
        resetLockTimer()
    })

	status := widget.NewLabel("Vault unlocked.")
	selectedIndex := -1

	mainClipboard := w.Clipboard()

    var entriesList *widget.List
    var filteredEntries []vault.Entry
    searchEntry := widget.NewEntry()
    searchEntry.SetPlaceHolder("Search services...")

    // Function to filter the main vault entries
    filterEntries := func(query string) {
        query = strings.ToLower(query)
        filteredEntries = nil 

        for i := range v.Entries {
            encServiceB, _ := base64.StdEncoding.DecodeString(v.Entries[i].Service)
            serviceBytes, _ := crypto.DecryptEntry(dek, encServiceB)
            serviceStr := strings.ToLower(string(serviceBytes))

            if query == "" || strings.Contains(serviceStr, query) {
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
			encServiceB, _ := base64.StdEncoding.DecodeString(filteredEntries[i].Service)
			serviceBytes, _ := crypto.DecryptEntry(dek, encServiceB)
			o.(*widget.Label).SetText(string(serviceBytes))
		},
	)

    searchEntry.OnChanged = func(s string) {
        resetLockTimer() 
        filterEntries(s)
    }

	entriesList.OnSelected = func(id widget.ListItemID) {
        resetLockTimer() 
		selectedIndex = int(id)
		status.SetText("")
	}
	entriesList.OnUnselected = func(id widget.ListItemID) {
        resetLockTimer() 
		if selectedIndex == int(id) {
			selectedIndex = -1
		}
	}

	addBtn := widget.NewButton("➕ Add", func() {
        resetLockTimer() 
		showAddEntryWindow(a, v, dek, entriesList, status)
        filterEntries(searchEntry.Text)
	})

	viewBtn := widget.NewButton("🔍 View", func() {
        resetLockTimer() 
		if selectedIndex < 0 {
			status.SetText("Select an entry first")
			return
		}
		e := filteredEntries[selectedIndex] 

		encServiceB, _ := base64.StdEncoding.DecodeString(e.Service)
		serviceBytes, _ := crypto.DecryptEntry(dek, encServiceB)
		serviceStr := string(serviceBytes)

		encUser, _ := base64.StdEncoding.DecodeString(e.Username)
		encPass, _ := base64.StdEncoding.DecodeString(e.Password)

		user, _ := crypto.DecryptEntry(dek, encUser)
		pass, _ := crypto.DecryptEntry(dek, encPass)
		passwordStr := string(pass)

		win := a.NewWindow("Entry")
		win.SetFixedSize(true)
		win.Resize(fyne.NewSize(450, 200))

		copyButton := widget.NewButton("📋 Copy Password (Auto-Clear)", func() {
            resetLockTimer() 
			mainClipboard.SetContent(passwordStr)

			status.SetText(fmt.Sprintf("Password copied! Clearing clipboard in %s.", clipboardTimeout))
			status.Refresh()

			time.AfterFunc(clipboardTimeout, func() {
				fyne.Do(func() {
					if mainClipboard.Content() == passwordStr {
						mainClipboard.SetContent("")
						status.SetText("Clipboard cleared successfully.")
					} else {
						status.SetText("Clipboard content changed/overwritten.")
					}
					status.Refresh()
				})
			})
		})

		win.SetContent(container.NewVBox(
			widget.NewLabel("Service: "+serviceStr),
			widget.NewSeparator(),
			widget.NewLabel("Username: "+string(user)),
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
        
        entryToDelete := filteredEntries[selectedIndex]
        masterIndex := -1
        for i, entry := range v.Entries {
            if entry.Service == entryToDelete.Service && entry.Username == entryToDelete.Username {
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
            status.SetText("Error: Entry not found in master list.")
        }
	})

	logoutBtn := widget.NewButton("🚪 Logout", func() {
        if vaultTimer != nil {
            vaultTimer.Stop() 
        }
        currentVaultWindow = nil 
		w.Close()
		showLoginWindow(a)
	})

	topButtons := container.NewHBox(addBtn, viewBtn, deleteBtn, logoutBtn)
    
	content := container.NewBorder(
        container.NewVBox(searchEntry, container.NewPadded(topButtons)), 
        status, 
        nil, 
        nil, 
        entriesList,
    )
	w.SetContent(content)
	w.Show()
}

// ---------------- ADD ENTRY WINDOW ----------------

func showAddEntryWindow(a fyne.App, v *vault.Vault, dek []byte, list *widget.List, status *widget.Label) {
    resetLockTimer() 
    
	w := a.NewWindow("Add Entry")
	w.SetFixedSize(true)
	w.Resize(fyne.NewSize(450, 350))

	service := widget.NewEntry()
	service.SetPlaceHolder("Service (e.g. Gmail)")
    service.OnChanged = func(s string) { resetLockTimer() } 
	serviceBox := container.NewPadded(service)

	username := widget.NewEntry()
	username.SetPlaceHolder("Username/email")
    username.OnChanged = func(s string) { resetLockTimer() } 
	usernameBox := container.NewPadded(username)

	pw := widget.NewPasswordEntry()
	pw.SetPlaceHolder("Account password")
	pwBox := container.NewPadded(pw)

	strengthLabel := widget.NewLabel("Strength:")
	strengthLabel.TextStyle.Bold = true

	indicatorText := widget.NewLabel("")
	indicatorText.TextStyle.Bold = true

	indicatorBar := widget.NewProgressBar()
	indicatorBar.Min = 0.0
	indicatorBar.Max = 1.0

	progressTheme := func(c color.Color) fyne.Theme {
		return &customTheme{
			base: theme.DefaultTheme(),
			color: c,
		}
	}
	
	updateIndicator := func(s string) {
        resetLockTimer() 
		text, score := scorePassword(s)
		
		var barColor color.Color
		if score < 0.33 {
			barColor = color.RGBA{R: 200, G: 0, B: 0, A: 255} 
		} else if score < 0.66 {
			barColor = color.RGBA{R: 255, G: 165, B: 0, A: 255} 
		} else {
			barColor = color.RGBA{R: 0, G: 150, B: 0, A: 255} 
		}

        fyne.Do(func() {
            indicatorText.SetText(text)
            indicatorBar.SetValue(score)
            
            a.Settings().SetTheme(progressTheme(barColor))

            indicatorText.Refresh()
            indicatorBar.Refresh()
        })
	}

	updateIndicator(pw.Text)

	indicatorTextBar := container.NewVBox(indicatorBar, container.NewHBox(indicatorText))
	indicatorBox := container.NewHBox(strengthLabel, indicatorTextBar)

	pw.OnChanged = updateIndicator

	save := widget.NewButton("Save", func() {
        resetLockTimer() 
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
		
		fyne.Do(func() {
			list.Refresh()
			status.SetText("Entry added ✅")
			w.Close()
			a.Settings().SetTheme(theme.DefaultTheme())
		})
	})

	w.SetContent(container.NewVBox(
		widget.NewLabel("Add New Entry"),
		serviceBox,
		usernameBox,
		pwBox,
		indicatorBox,
		save,
	))
	w.Show()
}
	
