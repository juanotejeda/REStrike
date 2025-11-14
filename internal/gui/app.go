package gui

import (
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/widget"
)

func RunGUI() {
	a := app.New()
	w := a.NewWindow("REStrike - Pentesting Toolkit")
	w.Resize(fyne.NewSize(900, 600))
	label := widget.NewLabel("Bienvenido a REStrike - Plataforma visual pentesting")
	w.SetContent(label)
	w.ShowAndRun()
}
