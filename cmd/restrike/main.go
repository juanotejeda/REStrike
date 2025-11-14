package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/juanotejeda/REStrike/internal/storage"
	"github.com/sirupsen/logrus"
)

var (
	version = "0.1.0"
	commit  = "dev"
)

func main() {
	// Flags
	verbose := flag.Bool("v", false, "Verbose output")
	headless := flag.Bool("headless", false, "Modo headless (sin GUI)")
	target := flag.String("target", "", "Target para escaneo directo")
	flag.Parse()

	// Setup logging
	logger := setupLogger(*verbose)
	logger.Infof("REStrike v%s (%s) iniciando...", version, commit)

	// Crear directorio de datos
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".restrike")
	os.MkdirAll(dataDir, 0700)

	// Inicializar base de datos
	dbPath := filepath.Join(dataDir, "restrike.db")
	db, err := storage.NewDatabase(dbPath, logger)
	if err != nil {
		logger.Fatalf("Error inicializando BD: %v", err)
	}
	defer db.Close()

	// Si es headless, ejecutar escaneo directo
	if *headless && *target != "" {
		fmt.Printf("Modo headless: escaneo de %s\n", *target)
		logger.Infof("Escaneo headless contra: %s", *target)
		return
	}

	// Iniciar GUI
	startGUI(logger, db)
}

func setupLogger(verbose bool) *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(os.Stdout)

	if verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})

	return logger
}

func startGUI(logger *logrus.Logger, db *storage.Database) {
	myApp := app.New()
	myWindow := myApp.NewWindow()
	myWindow.SetTitle("REStrike - Pentesting Tool")
	myWindow.Resize(fyne.NewSize(1200, 800))

	// Welcome screen
	title := widget.NewLabelWithAlignment("REStrike v0.1.0", fyne.TextAlignCenter)
	subtitle := widget.NewLabelWithAlignment("Herramienta de Pentesting Visual para #RE Community", fyne.TextAlignCenter)

	startBtn := widget.NewButton("Nuevo Escaneo", func() {
		logger.Info("Iniciando nuevo escaneo...")
		fmt.Println("Botón de escaneo presionado")
	})

	helpLabel := widget.NewLabel("Selecciona una opción para comenzar")

	content := container.NewVBox(
		title,
		subtitle,
		widget.NewSeparator(),
		helpLabel,
		startBtn,
	)

	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}
