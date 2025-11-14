package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/juanotejeda/REStrike/internal/storage"
)

// Logger interface
type Logger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// App aplicación principal GUI
type App struct {
	logger Logger
	db     *storage.Database
	window fyne.Window
}

// NewApp crea nueva aplicación GUI
func NewApp(window fyne.Window, logger Logger, db *storage.Database) *App {
	return &App{
		logger: logger,
		db:     db,
		window: window,
	}
}

// CreateMainContent crea contenido principal
func (a *App) CreateMainContent() *fyne.Container {
	// Tabs principales
	tabs := container.NewAppTabs(
		container.NewTabItem("Dashboard", a.createDashboard()),
		container.NewTabItem("Escaneo", a.createScanTab()),
		container.NewTabItem("Vulnerabilidades", a.createVulnTab()),
		container.NewTabItem("Exploits", a.createExploitTab()),
		container.NewTabItem("Reportes", a.createReportTab()),
	)

	return tabs
}

// createDashboard crea tab de dashboard
func (a *App) createDashboard() *fyne.Container {
	statsLabel := widget.NewLabel("Dashboard - Estadísticas")
	hostsLabel := widget.NewLabel("Hosts escaneados: 0")
	vulnsLabel := widget.NewLabel("Vulnerabilidades: 0")

	content := container.NewVBox(
		statsLabel,
		widget.NewSeparator(),
		hostsLabel,
		vulnsLabel,
	)

	return content
}

// createScanTab crea tab de escaneo
func (a *App) createScanTab() *fyne.Container {
	targetInput := widget.NewEntry()
	targetInput.SetPlaceHolder("Ej: 192.168.1.0/24 o 192.168.1.1")

	portsInput := widget.NewEntry()
	portsInput.SetPlaceHolder("Ej: 1-1000 o 22,80,443")
	portsInput.SetText("1-1000")

	aggressiveCheck := widget.NewCheck("Modo Agresivo", func(b bool) {
		a.logger.Debugf("Modo agresivo: %v", b)
	})

	scanBtn := widget.NewButton("Iniciar Escaneo", func() {
		a.logger.Infof("Escaneo iniciado para: %s", targetInput.Text)
	})

	content := container.NewVBox(
		widget.NewLabel("Nuevo Escaneo"),
		widget.NewSeparator(),
		widget.NewLabel("Target:"),
		targetInput,
		widget.NewLabel("Puertos:"),
		portsInput,
		aggressiveCheck,
		widget.NewSeparator(),
		scanBtn,
	)

	return content
}

// createVulnTab crea tab de vulnerabilidades
func (a *App) createVulnTab() *fyne.Container {
	vulnList := widget.NewList(
		func() int { return 0 },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, co fyne.CanvasObject) {},
	)

	content := container.NewVBox(
		widget.NewLabel("Vulnerabilidades Detectadas"),
		widget.NewSeparator(),
		vulnList,
	)

	return content
}

// createExploitTab crea tab de exploits
func (a *App) createExploitTab() *fyne.Container {
	moduleInput := widget.NewEntry()
	moduleInput.SetPlaceHolder("Ej: windows/smb/ms17_010_eternalblue")

	targetInput := widget.NewEntry()
	targetInput.SetPlaceHolder("Target IP")

	executeBtn := widget.NewButton("Ejecutar Exploit", func() {
		a.logger.Infof("Exploit ejecutado contra: %s", targetInput.Text)
	})

	content := container.NewVBox(
		widget.NewLabel("Módulo Exploit"),
		moduleInput,
		widget.NewLabel("Target:"),
		targetInput,
		widget.NewSeparator(),
		executeBtn,
	)

	return content
}

// createReportTab crea tab de reportes
func (a *App) createReportTab() *fyne.Container {
	generateBtn := widget.NewButton("Generar Reporte PDF", func() {
		a.logger.Infof("Generando reporte...")
	})

	htmlBtn := widget.NewButton("Generar Reporte HTML", func() {
		a.logger.Infof("Generando reporte HTML...")
	})

	content := container.NewVBox(
		widget.NewLabel("Generador de Reportes"),
		widget.NewSeparator(),
		generateBtn,
		htmlBtn,
	)

	return content
}
