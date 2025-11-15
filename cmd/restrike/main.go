package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/juanotejeda/REStrike/internal/scanner"
	"github.com/juanotejeda/REStrike/internal/storage"
	"github.com/sirupsen/logrus"
)

var (
	version = "0.1.0"
	commit  = "dev"
)

func main() {
	verbose := flag.Bool("v", false, "Verbose output")
	headless := flag.Bool("headless", false, "Modo headless (sin GUI)")
	target := flag.String("target", "", "Target para escaneo directo")
	flag.Parse()

	logger := setupLogger(*verbose)
	logger.Infof("REStrike v%s (%s) iniciando...", version, commit)

	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".restrike")
	os.MkdirAll(dataDir, 0700)

	dbPath := filepath.Join(dataDir, "restrike.db")
	db, err := storage.NewDatabase(dbPath, logger)
	if err != nil {
		logger.Fatalf("Error inicializando BD: %v", err)
	}
	defer db.Close()

	if *headless && *target != "" {
		logger.Infof("Modo headless: escaneo de %s", *target)
		runHeadlessScan(logger, *target)
		return
	}

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
	myWindow := myApp.NewWindow("REStrike - Pentesting Tool")
	myWindow.Resize(fyne.NewSize(1200, 800))

	scan := scanner.NewScanner(logger)

	showMainScreen(myWindow, logger, scan)

	myWindow.ShowAndRun()
}

func showMainScreen(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner) {
	title := widget.NewLabel("REStrike v0.1.0")
	title.Alignment = fyne.TextAlignCenter

	subtitle := widget.NewLabel("Herramienta de Pentesting Visual para #RE Community")
	subtitle.Alignment = fyne.TextAlignCenter

	startBtn := widget.NewButton("Nuevo Escaneo", func() {
		logger.Info("Abriendo formulario de escaneo...")
		showScanForm(myWindow, logger, scan)
	})

	exitBtn := widget.NewButton("Salir", func() {
		logger.Info("Aplicación cerrada")
		os.Exit(0)
	})

	buttons := container.NewHBox(startBtn, exitBtn)

	content := container.NewVBox(
		title,
		subtitle,
		widget.NewSeparator(),
		buttons,
	)

	myWindow.SetContent(content)
}

func showScanForm(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner) {
	targetEntry := widget.NewEntry()
	targetEntry.SetPlaceHolder("ej: 192.168.1.0/24, 127.0.0.1, o 192.168.1.1-10")

	targetLabel := widget.NewLabel("Target a escanear (IP, rango o CIDR):")

	scanBtn := widget.NewButton("Iniciar Escaneo", func() {
		target := targetEntry.Text
		if target == "" {
			logger.Warn("Target vacío")
			return
		}

		logger.Infof("Iniciando escaneo de: %s", target)
		showScanResults(myWindow, logger, scan, target)
	})

	backBtn := widget.NewButton("Volver", func() {
		logger.Info("Volviendo al menú principal...")
		showMainScreen(myWindow, logger, scan)
	})

	targetEntry.OnSubmitted = func(s string) {
		if s != "" {
			logger.Infof("Iniciando escaneo de: %s", s)
			showScanResults(myWindow, logger, scan, s)
		}
	}

	buttons := container.NewHBox(scanBtn, backBtn)

	form := container.NewVBox(
		widget.NewLabel("Configuración de Escaneo"),
		widget.NewSeparator(),
		targetLabel,
		targetEntry,
		widget.NewSeparator(),
		widget.NewLabel("Formatos soportados:"),
		widget.NewLabel("• IP simple: 127.0.0.1"),
		widget.NewLabel("• CIDR: 192.168.1.0/24"),
		widget.NewLabel("• Rango: 192.168.1.1-10"),
		widget.NewLabel("• Hostname: google.com"),
		widget.NewSeparator(),
		buttons,
	)

	scroll := container.NewScroll(form)
	myWindow.SetContent(scroll)
}

func showScanResults(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, target string) {
	statusLabel := widget.NewLabel(fmt.Sprintf("Escaneando: %s", target))
	statusLabel.Alignment = fyne.TextAlignCenter

	elapsedLabel := widget.NewLabel("Tiempo transcurrido: 0s")
	elapsedLabel.Alignment = fyne.TextAlignCenter

	resultsText := widget.NewLabel("Escaneando... Por favor espera.")
	resultsText.Alignment = fyne.TextAlignLeading

	backBtn := widget.NewButton("Volver", func() {
		logger.Info("Volviendo al menú principal...")
		showMainScreen(myWindow, logger, scan)
	})
	backBtn.Disable()

	// Declarar cancelBtn como pointer para poder usarlo en su propio callback
	var cancelBtn *widget.Button
	cancelBtn = widget.NewButton("Cancelar Escaneo", func() {
		logger.Warn("Cancelando escaneo...")
		resultsText.SetText("Escaneo cancelado por el usuario.")
		cancelBtn.Disable()
		backBtn.Enable()
	})

	buttons := container.NewHBox(cancelBtn, backBtn)

	results := container.NewVBox(
		statusLabel,
		widget.NewSeparator(),
		elapsedLabel,
		widget.NewSeparator(),
		resultsText,
		widget.NewSeparator(),
		buttons,
	)

	scroll := container.NewScroll(results)
	myWindow.SetContent(scroll)

	ticker := time.NewTicker(1 * time.Second)
	frameIndex := 0
	spinChars := []string{"|", "/", "-", "\\"}

	go func() {
		startTime := time.Now()

		for range ticker.C {
			elapsed := time.Since(startTime)
			frameIndex = (frameIndex + 1) % len(spinChars)
			elapsedLabel.SetText(fmt.Sprintf("%s Tiempo transcurrido: %v", spinChars[frameIndex], elapsed.Round(time.Second)))
		}
	}()

	go func() {
		startTime := time.Now()
		logger.Infof("Escaneo iniciado a las %s", startTime.Format("15:04:05"))

		ctx := context.Background()
		result, err := scan.ScanNetwork(ctx, target)

		ticker.Stop()

		if err != nil {
			logger.Errorf("Error en escaneo: %v", err)
			resultsText.SetText(fmt.Sprintf("ERROR en escaneo:\n%v\n\nIntenta con 'sudo' si necesitas permisos elevados.\nEjemplo: sudo ./restrike", err))
			cancelBtn.Disable()
			backBtn.Enable()
			return
		}

		duration := time.Since(startTime)

		report := fmt.Sprintf("ESCANEO COMPLETADO\n\n"+
			"Target: %s\n"+
			"Hosts encontrados: %d\n"+
			"Duracion total: %v\n"+
			"Inicio: %s\n"+
			"Fin: %s\n\n"+
			"═══════════════════════════════════\n\n",
			result.Target,
			result.TotalHosts,
			duration,
			result.StartTime.Format("15:04:05"),
			result.EndTime.Format("15:04:05"),
		)

		if len(result.Hosts) > 0 {
			report += "HOSTS DESCUBIERTOS:\n\n"
			for i, host := range result.Hosts {
				report += fmt.Sprintf("%d. %s\n", i+1, host.IP)
				if host.Hostname != "" {
					report += fmt.Sprintf("   Hostname: %s\n", host.Hostname)
				}
				report += fmt.Sprintf("   Estado: %s\n", host.Status)
				if host.OS != "" {
					report += fmt.Sprintf("   SO: %s\n", host.OS)
				}

				if len(host.Ports) > 0 {
					report += "   Puertos:\n"
					for _, port := range host.Ports {
						service := port.Service
						if port.Version != "" {
							service = fmt.Sprintf("%s (%s)", port.Service, port.Version)
						}
						report += fmt.Sprintf("     - %d/%s: %s [%s]\n",
							port.ID,
							port.Protocol,
							port.State,
							service,
						)
					}
				}
				report += "\n"
			}
		} else {
			report += "No se encontraron hosts activos.\n"
		}

		resultsText.SetText(report)
		cancelBtn.Disable()
		backBtn.Enable()

		logger.Infof("Escaneo completado: %d hosts en %v", result.TotalHosts, duration)
	}()
}

func runHeadlessScan(logger *logrus.Logger, target string) {
	logger.Infof("Ejecutando escaneo headless contra: %s", target)
	scan := scanner.NewScanner(logger)
	ctx := context.Background()
	result, err := scan.ScanNetwork(ctx, target)
	if err != nil {
		logger.Errorf("Error en escaneo: %v", err)
		return
	}
	logger.Infof("Escaneo completado: %d hosts encontrados", result.TotalHosts)
}
