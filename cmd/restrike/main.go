package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/juanotejeda/REStrike/internal/export"
	"github.com/juanotejeda/REStrike/pkg/models"
	"github.com/juanotejeda/REStrike/internal/scanner"
	"github.com/juanotejeda/REStrike/internal/storage"
	"github.com/juanotejeda/REStrike/internal/comparison"
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

		// Obtener directorio home - si estamos en sudo, usar /root
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir, _ = os.UserHomeDir()
	}
	dataDir := filepath.Join(homeDir, ".restrike")
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		logger.Warnf("Error creando directorio: %v", err)
	}


	dbPath := filepath.Join(dataDir, "restrike.db")
	db, err := storage.NewDatabase(dbPath, logger)
	if err != nil {
		logger.Fatalf("Error inicializando BD: %v", err)
	}
	defer db.Close()

	if *headless && *target != "" {
		logger.Infof("Modo headless: escaneo de %s", *target)
		runHeadlessScan(logger, db, *target)
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

	showMainScreen(myWindow, logger, scan, db)

	myWindow.ShowAndRun()
}

func showMainScreen(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database) {
	title := widget.NewLabel("REStrike v0.1.0")
	title.Alignment = fyne.TextAlignCenter

	subtitle := widget.NewLabel("Herramienta de Pentesting Visual para #RE Community")
	subtitle.Alignment = fyne.TextAlignCenter

		startBtn := widget.NewButton("Nuevo Escaneo", func() {
		logger.Info("Abriendo formulario de escaneo...")
		showScanForm(myWindow, logger, scan, db)
	})

	historyBtn := widget.NewButton("Ver Historial", func() {
		logger.Info("Abriendo historial...")
		showScanHistory(myWindow, logger, scan, db)
	})

	exitBtn := widget.NewButton("Salir", func() {
		logger.Info("Aplicación cerrada")
		os.Exit(0)
	})

	buttons := container.NewHBox(startBtn, historyBtn, exitBtn)


	content := container.NewVBox(
		title,
		subtitle,
		widget.NewSeparator(),
		buttons,
	)

	myWindow.SetContent(content)
}

func showScanForm(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database) {
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
		showScanResults(myWindow, logger, scan, db, target)
	})

	backBtn := widget.NewButton("Volver", func() {
		logger.Info("Volviendo al menú principal...")
		showMainScreen(myWindow, logger, scan, db)
	})

	targetEntry.OnSubmitted = func(s string) {
		if s != "" {
			logger.Infof("Iniciando escaneo de: %s", s)
			showScanResults(myWindow, logger, scan, db, s)
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

func showScanResults(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database, target string) {
	statusLabel := widget.NewLabel(fmt.Sprintf("Escaneando: %s", target))
	statusLabel.Alignment = fyne.TextAlignCenter

	elapsedLabel := widget.NewLabel("Tiempo transcurrido: 0s")
	elapsedLabel.Alignment = fyne.TextAlignCenter

	resultsText := widget.NewLabel("Escaneando... Por favor espera.")
	resultsText.Alignment = fyne.TextAlignLeading

	backBtn := widget.NewButton("Volver", func() {
		logger.Info("Volviendo al menú principal...")
		showMainScreen(myWindow, logger, scan, db)
	})
	backBtn.Disable()

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

		// Guardar en BD
		scanID := fmt.Sprintf("%d", time.Now().UnixNano())
		jsonData, _ := json.Marshal(result)
		err2 := db.SaveScanComplete(scanID, target, result.StartTime, result.EndTime, result.TotalHosts, result.StatusCode, jsonData)
		if err2 != nil {
			logger.Warnf("Error guardando en BD: %v", err2)
		} else {
			logger.Infof("Escaneo guardado en BD con ID: %s", scanID)
		}

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
						report += fmt.Sprintf("     - %d/%s: %s [%s]",
							port.ID,
							port.Protocol,
							port.State,
							service,
						)

						// Verificar vulnerabilidades
						vulns := scanner.GetVulnerabilitiesForPort(port.ID, port.Protocol, port.Service)
						if len(vulns) > 0 {
							for _, vuln := range vulns {
								report += fmt.Sprintf("\n       ⚠️  %s\n       %s\n", scanner.RiskLevel(vuln.Risk), vuln.Description)
							}
						}
						report += "\n"
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

func showScanHistory(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database) {
	scans, err := db.GetAllScans()
	if err != nil {
		logger.Errorf("Error obteniendo historial: %v", err)
		return
	}

	backBtn := widget.NewButton("Volver", func() {
		logger.Info("Volviendo al menú principal...")
		showMainScreen(myWindow, logger, scan, db)
	})

	compareBtn := widget.NewButton("Comparar 2 Escaneos", func() {
		logger.Info("Iniciando comparación...")
		showCompareSelection(myWindow, logger, scan, db, scans)
	})

	if len(scans) == 0 {
		content := container.NewVBox(
			widget.NewLabel("No hay escaneos guardados"),
			widget.NewSeparator(),
			backBtn,
		)
		myWindow.SetContent(content)
		return
	}

	items := container.NewVBox()
	for _, s := range scans {
		scanID := s.ID
		scanItem := widget.NewButton(fmt.Sprintf("%s - %s (%d hosts)", s.Target, s.Timestamp, s.TotalHosts), (func(id string) func() {
			return func() {
				logger.Infof("Ver detalles del escaneo: %s", id)
				showScanDetail(myWindow, logger, scan, db, scanID)
			}
		}(s.ID)))
		items.Add(scanItem)
	}

	scroll := container.NewScroll(items)
	scroll.SetMinSize(fyne.NewSize(700, 400))

	buttons := container.NewHBox(compareBtn, backBtn)

	content := container.NewBorder(
		container.NewVBox(
			widget.NewLabel("Historial de Escaneos"),
			widget.NewSeparator(),
		),
		container.NewVBox(
			widget.NewSeparator(),
			buttons,
		),
		nil,
		nil,
		scroll,
	)

	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(800, 600))
}

func showScanDetail(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database, scanID string) {
	data, err := db.GetScanData(scanID)
	if err != nil {
		logger.Errorf("Error obteniendo escaneo: %v", err)
		return
	}

	// Parse JSON para obtener ScanResult
	var result models.ScanResult
	json.Unmarshal([]byte(data), &result)

	backBtn := widget.NewButton("Volver", func() {
		logger.Info("Volviendo al historial...")
		showScanHistory(myWindow, logger, scan, db)
	})

	exportPDFBtn := widget.NewButton("Exportar PDF", func() {
		filename := fmt.Sprintf("escaneo_%s_%s.pdf", result.Target, time.Now().Format("20060102_150405"))
		err := export.ExportToPDF(filename, &result)
		if err != nil {
			logger.Errorf("Error exportando PDF: %v", err)
		} else {
			logger.Infof("PDF exportado: %s", filename)
		}
	})

	buttons := container.NewHBox(exportPDFBtn, backBtn)

	resultsEntry := widget.NewMultiLineEntry()
	resultsEntry.SetText(data)
	resultsEntry.Wrapping = fyne.TextWrapWord
	resultsEntry.Disable()

	scroll := container.NewScroll(resultsEntry)
	scroll.SetMinSize(fyne.NewSize(700, 500))

	content := container.NewBorder(
		container.NewVBox(
			widget.NewLabel("Detalles del Escaneo"),
			widget.NewSeparator(),
		),
		container.NewVBox(
			widget.NewSeparator(),
			buttons,
		),
		nil,
		nil,
		scroll,
	)

	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(800, 600))
}

func showCompareSelection(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database, scans []storage.ScanInfo) {
	if len(scans) < 2 {
		content := container.NewVBox(
			widget.NewLabel("Necesitas al menos 2 escaneos para comparar"),
			widget.NewSeparator(),
			widget.NewButton("Volver", func() {
				showScanHistory(myWindow, logger, scan, db)
			}),
		)
		myWindow.SetContent(content)
		return
	}

	var selectedScans []string
	var checkboxes []*widget.Check

	// Función para actualizar estado de checkboxes
	updateCheckboxStates := func() {
		for _, cb := range checkboxes {
			if len(selectedScans) >= 2 && !cb.Checked {
				cb.Disable()
			} else {
				cb.Enable()
			}
		}
	}

	items := container.NewVBox()
	for _, s := range scans {
		scanInfo := s
		check := widget.NewCheck(fmt.Sprintf("%s - %s (%d hosts)", scanInfo.Target, scanInfo.Timestamp, scanInfo.TotalHosts), func(checked bool) {
			if checked {
				selectedScans = append(selectedScans, scanInfo.ID)
			} else {
				// Remover de selectedScans
				for i, id := range selectedScans {
					if id == scanInfo.ID {
						selectedScans = append(selectedScans[:i], selectedScans[i+1:]...)
						break
					}
				}
			}
			updateCheckboxStates()
		})
		checkboxes = append(checkboxes, check)
		items.Add(check)
	}

	compareBtn := widget.NewButton("Comparar Seleccionados", func() {
		if len(selectedScans) != 2 {
			logger.Warn("Debes seleccionar exactamente 2 escaneos")
			return
		}
		logger.Infof("Comparando: %s vs %s", selectedScans[0], selectedScans[1])
		showComparisonResult(myWindow, logger, scan, db, selectedScans[0], selectedScans[1])
	})

	backBtn := widget.NewButton("Volver", func() {
		showScanHistory(myWindow, logger, scan, db)
	})

	buttons := container.NewHBox(compareBtn, backBtn)
	scroll := container.NewScroll(items)
	scroll.SetMinSize(fyne.NewSize(700, 400))

	content := container.NewBorder(
		container.NewVBox(
			widget.NewLabel("Selecciona 2 escaneos para comparar (máximo 2)"),
			widget.NewSeparator(),
		),
		container.NewVBox(
			widget.NewSeparator(),
			buttons,
		),
		nil,
		nil,
		scroll,
	)

	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(800, 600))
}


func showComparisonResult(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database, scanID1, scanID2 string) {
	// Obtener datos de ambos escaneos
	data1, err1 := db.GetScanData(scanID1)
	data2, err2 := db.GetScanData(scanID2)

	if err1 != nil || err2 != nil {
		logger.Errorf("Error obteniendo escaneos: %v %v", err1, err2)
		return
	}

	var scan1, scan2 models.ScanResult
	json.Unmarshal([]byte(data1), &scan1)
	json.Unmarshal([]byte(data2), &scan2)

	// Comparar
	compResult := comparison.CompareScanResults(&scan1, &scan2)

	backBtn := widget.NewButton("Volver", func() {
		showScanHistory(myWindow, logger, scan, db)
	})

	// Usar Entry multilínea en lugar de Label
	resultsEntry := widget.NewMultiLineEntry()
	resultsEntry.SetText(compResult.Summary)
	resultsEntry.Wrapping = fyne.TextWrapWord
	resultsEntry.Disable() // Solo lectura

	scroll := container.NewScroll(resultsEntry)
	scroll.SetMinSize(fyne.NewSize(700, 500)) // Tamaño mínimo

	content := container.NewBorder(
		container.NewVBox(
			widget.NewLabel("Resultado de Comparación"),
			widget.NewSeparator(),
		),
		container.NewVBox(
			widget.NewSeparator(),
			backBtn,
		),
		nil,
		nil,
		scroll,
	)

	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(800, 600)) // Redimensionar ventana
}


func runHeadlessScan(logger *logrus.Logger, db *storage.Database, target string) {
	logger.Infof("Ejecutando escaneo headless contra: %s", target)
	scan := scanner.NewScanner(logger)
	ctx := context.Background()
	result, err := scan.ScanNetwork(ctx, target)
	if err != nil {
		logger.Errorf("Error en escaneo: %v", err)
		return
	}

	scanID := fmt.Sprintf("%d", time.Now().UnixNano())
	jsonData, _ := json.Marshal(result)
	db.SaveScan(scanID, target, jsonData)

	logger.Infof("Escaneo completado: %d hosts encontrados", result.TotalHosts)
}
