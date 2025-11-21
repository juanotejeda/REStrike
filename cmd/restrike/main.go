package main

import (
	"strings"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"time"
	"os/exec"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/juanotejeda/REStrike/internal/export"
	"github.com/juanotejeda/REStrike/pkg/models"
	"github.com/juanotejeda/REStrike/internal/scanner"
	"github.com/juanotejeda/REStrike/internal/storage"
	"github.com/juanotejeda/REStrike/internal/comparison"
	"github.com/juanotejeda/REStrike/internal/msf"
	"github.com/sirupsen/logrus"
)

var (
	version = "0.1.0"
	commit  = "dev"
)
var uiLogs []string
const maxUILogs = 50

func appendUILog(log string) {
	if len(uiLogs) >= maxUILogs {
		uiLogs = uiLogs[1:]
	}
	uiLogs = append(uiLogs, log)
}

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
	logger.AddHook(&UILogHook{})
	return logger
}
type UILogHook struct{}

func (h *UILogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *UILogHook) Fire(e *logrus.Entry) error {
	logstr := fmt.Sprintf("[%s] %s", strings.ToUpper(e.Level.String()), e.Message)
	appendUILog(logstr)
	return nil
}

func startGUI(logger *logrus.Logger, db *storage.Database) {
	myApp := app.New()
	myApp.Settings().SetTheme(&cyberpunkTheme{})
	myWindow := myApp.NewWindow("REStrike - Pentesting Tool")
	myWindow.Resize(fyne.NewSize(1200, 800))

	scan := scanner.NewScanner(logger)

	showMainScreen(myWindow, logger, scan, db)

	myWindow.ShowAndRun()
}

func showDashboard(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database) {
	logger.Info("Mostrando dashboard principal...")

	// Barra de estado inferior
	statusLabel := widget.NewLabelWithStyle("Listo.", fyne.TextAlignTrailing, fyne.TextStyle{Bold: true, Monospace: true})

	// Verificar msfrpcd corriendo
	isMsfRpcdRunning := func() bool {
		cmd := exec.Command("pgrep", "-f", "msfrpcd -P mypassword123 -S -a 127.0.0.1 -p 55553")
		return cmd.Run() == nil
	}

	var startMsfBtn *widget.Button
	if !isMsfRpcdRunning() {
		startMsfBtn = widget.NewButton("Iniciar msfrpcd", func() {
			go func() {
				cmd := exec.Command("msfrpcd", "-P", "mypassword123", "-S", "-a", "127.0.0.1", "-p", "55553")
				if err := cmd.Start(); err != nil {
					logger.Errorf("Error iniciando msfrpcd: %v", err)
					statusLabel.SetText("Error iniciando msfrpcd")
				} else {
					logger.Info("msfrpcd iniciado")
					statusLabel.SetText("msfrpcd iniciado 🎉")
					startMsfBtn.Disable()
				}
			}()
		})
		startMsfBtn.Importance = widget.HighImportance
	} else {
		startMsfBtn = widget.NewButton("msfrpcd corriendo", func() {})
		startMsfBtn.Disable()
	}

	backBtn := widget.NewButton("⬅ Volver", func() {
		showMainScreen(myWindow, logger, scan, db)
	})

	// ---------- ESCANEOS RECIENTES ----------
	scans, err := db.GetScanHistory(10)
	if err != nil {
		logger.Errorf("Error cargando historial: %v", err)
		scans = []storage.ScanInfo{}
	}

	recentList := container.NewVBox()
	maxScans := 5
	if len(scans) < 5 { maxScans = len(scans) }
	for i := 0; i < maxScans; i++ {
		s := scans[i]
		info := fmt.Sprintf("🎯 %s | Hosts: %d | %s", s.Target, s.TotalHosts, s.Timestamp)
		lbl := widget.NewLabelWithStyle(info, fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true})
		recentList.Add(lbl)
	}
	if maxScans == 0 {
		recentList.Add(widget.NewLabelWithStyle("Sin escaneos recientes", fyne.TextAlignCenter, fyne.TextStyle{Monospace: true}))
	}

	recentPanel := container.NewVBox(
		widget.NewLabelWithStyle("📊 ESCANEOS RECIENTES", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		recentList,
	)

	// ---------- ESTADÍSTICAS ----------
	totalScans := len(scans)
	statsPanel := container.NewVBox(
		widget.NewLabelWithStyle("📈 ESTADÍSTICAS", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		widget.NewLabelWithStyle(fmt.Sprintf("Total Escaneos: %d", totalScans), fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}),
		widget.NewLabelWithStyle(fmt.Sprintf("Última actividad: %s", time.Now().Format("15:04")), fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}),
	)

	// ---------- ACCIONES RÁPIDAS ----------
	newScanBtn := widget.NewButton("🔍 Nuevo Escaneo", func() {
		showScanForm(myWindow, logger, scan, db)
	})
	historyBtn := widget.NewButton("📋 Historial", func() {
		showScanHistory(myWindow, logger, scan, db)
	})
	compareBtn := widget.NewButton("⚖️ Comparar", func() {
		scans, _ := db.GetScanHistory(10)
		showCompareSelection(myWindow, logger, scan, db, scans)
	})
	actionsPanel := container.NewVBox(
		widget.NewLabelWithStyle("⚡ ACCIONES RÁPIDAS", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		newScanBtn,
		historyBtn,
		compareBtn,
		startMsfBtn,
		backBtn,
	)

	// ---------- PANEL IZQUIERDO DASHBOARD ----------
	leftPanel := container.NewVBox(
		recentPanel,
		statsPanel,
		actionsPanel,
	)
	leftScroll := container.NewVScroll(leftPanel)
	leftScroll.Resize(fyne.NewSize(600, 680))

	// ---------- SYSTEM LOG STREAM ----------
	logTitle := widget.NewLabelWithStyle("SYSTEM LOG STREAM", fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})

	maxLogs := 10
	startLog := 0
	if len(uiLogs) > maxLogs { startLog = len(uiLogs) - maxLogs }
	logsList := container.NewVBox()
	for _, logLine := range uiLogs[startLog:] {
		lbl := widget.NewLabelWithStyle(logLine, fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true})
		logsList.Add(lbl)
	}

// Scroll con altura mínima suficiente para que se lean 8–10 líneas
	logsScroll := container.NewVScroll(logsList)
	logsScroll.SetMinSize(fyne.NewSize(0, 200)) // Ajusta 200 para ~8 líneas, sube para más

	logPanel := container.NewVBox(
		logTitle,
		widget.NewSeparator(),
		logsScroll,
	)

	// Timer para refrescar logs (VBox)
	go func() {
		for {
			time.Sleep(2 * time.Second)
			for len(logsList.Objects) > 0 {
				logsList.Remove(logsList.Objects[0])
			}
			startLog := 0
			if len(uiLogs) > maxLogs { startLog = len(uiLogs) - maxLogs }
			for _, logLine := range uiLogs[startLog:] {
				lbl := widget.NewLabelWithStyle(logLine, fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true})
				logsList.Add(lbl)
			}
			logsList.Refresh()
		}
	}()

	// ---------- LAYOUT PRINCIPAL ----------
	split := container.NewHSplit(
		leftScroll,
		logPanel,
	)
	split.Offset = 0.50 // Mitad y mitad

	bottomBar := container.NewHBox(
		statusLabel,
	)

	title := widget.NewLabelWithStyle("⚡ RESTRIKE CYBERSTRIKE MODE ⚡", fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})

	content := container.NewBorder(
		container.NewVBox(title, widget.NewSeparator()), // arriba
		nil, nil,
		bottomBar, // abajo
		split,     // centro
	)

	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(1200, 720))
}


func showMainScreen(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database) {
	title := widget.NewLabel("REStrike v0.1.0")
	title.Alignment = fyne.TextAlignCenter

	subtitle := widget.NewLabel("Herramienta de Pentesting Visual para #RE Community")
	subtitle.Alignment = fyne.TextAlignCenter

		dashboardBtn := widget.NewButton("🚀 Dashboard", func() {
		showDashboard(myWindow, logger, scan, db)
	})
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

	buttons := container.NewHBox(dashboardBtn, startBtn, historyBtn, exitBtn)


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

	backBtn := widget.NewButton("Volver al Historial", func() {
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

	backBtn := widget.NewButton("Volver al Historial", func() {
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

	backBtn := widget.NewButton("Volver al Historial", func() {
		logger.Info("Volviendo al menú principal...")
		showMainScreen(myWindow, logger, scan, db)
	})

	compareBtn := widget.NewButton("Comparar 2 Escaneos", func() {
		logger.Info("Iniciando comparación...")
		showCompareSelection(myWindow, logger, scan, db, scans)
	})

	filterBtn := widget.NewButton("Filtrar", func() {
		logger.Info("Abriendo filtros...")
		showFilterDialog(myWindow, logger, scan, db)
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

	buttons := container.NewHBox(filterBtn, compareBtn, backBtn)

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

	backBtn := widget.NewButton("Volver al Historial", func() {
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

	exportJSONBtn := widget.NewButton("Exportar JSON", func() {
		filename := fmt.Sprintf("escaneo_%s_%s.json", result.Target, time.Now().Format("20060102_150405"))
		err := export.ExportToJSON(filename, &result)
		if err != nil {
			logger.Errorf("Error exportando JSON: %v", err)
		} else {
			logger.Infof("JSON exportado: %s", filename)
		}
	})

	exportCSVBtn := widget.NewButton("Exportar CSV", func() {
		filename := fmt.Sprintf("escaneo_%s_%s.csv", result.Target, time.Now().Format("20060102_150405"))
		err := export.ExportToCSV(filename, &result)
		if err != nil {
			logger.Errorf("Error exportando CSV: %v", err)
		} else {
			logger.Infof("CSV exportado: %s", filename)
		}
	})

	exploitsBtn := widget.NewButton("Sugerir Exploits", func() {
		logger.Info("Buscando exploits sugeridos...")
		showExploitSuggestions(myWindow, logger, scan, db, &result)
	})

	exportButtons := container.NewHBox(exportPDFBtn, exportJSONBtn, exportCSVBtn)
	actionButtons := container.NewHBox(exploitsBtn, exportButtons)
	buttons := container.NewHBox(actionButtons, backBtn)

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
			widget.NewButton("Volver al Historial", func() {
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

	backBtn := widget.NewButton("Volver al Historial", func() {
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

	backBtn := widget.NewButton("Volver al Historial", func() {
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

func showFilterDialog(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database) {
	targetEntry := widget.NewEntry()
	targetEntry.SetPlaceHolder("IP o target (ej: 192.168.1.0/24)")

	dateFromEntry := widget.NewEntry()
	dateFromEntry.SetPlaceHolder("Fecha desde (ej: 2025-11-01)")

	dateToEntry := widget.NewEntry()
	dateToEntry.SetPlaceHolder("Fecha hasta (ej: 2025-11-30)")

	minHostsEntry := widget.NewEntry()
	minHostsEntry.SetPlaceHolder("Mínimo hosts (ej: 5)")

	searchBtn := widget.NewButton("Buscar", func() {
		target := targetEntry.Text
		dateFrom := dateFromEntry.Text
		dateTo := dateToEntry.Text
		minHosts := 0
		
		if minHostsEntry.Text != "" {
			fmt.Sscanf(minHostsEntry.Text, "%d", &minHosts)
		}

		logger.Infof("Buscando: target=%s, desde=%s, hasta=%s, minHosts=%d", target, dateFrom, dateTo, minHosts)
		
		scans, err := db.SearchScans(target, dateFrom, dateTo, minHosts)
		if err != nil {
			logger.Errorf("Error en búsqueda: %v", err)
			return
		}

		showFilteredResults(myWindow, logger, scan, db, scans)
	})

	clearBtn := widget.NewButton("Limpiar Filtros", func() {
		showScanHistory(myWindow, logger, scan, db)
	})

	backBtn := widget.NewButton("Volver al Historial", func() {
		showScanHistory(myWindow, logger, scan, db)
	})

	form := container.NewVBox(
		widget.NewLabel("Filtros de Búsqueda"),
		widget.NewSeparator(),
		widget.NewLabel("Target/IP:"),
		targetEntry,
		widget.NewLabel("Fecha desde (YYYY-MM-DD):"),
		dateFromEntry,
		widget.NewLabel("Fecha hasta (YYYY-MM-DD):"),
		dateToEntry,
		widget.NewLabel("Mínimo de hosts:"),
		minHostsEntry,
		widget.NewSeparator(),
		container.NewHBox(searchBtn, clearBtn, backBtn),
	)

	scroll := container.NewScroll(form)
	myWindow.SetContent(scroll)
	myWindow.Resize(fyne.NewSize(600, 500))
}

func showFilteredResults(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database, scans []storage.ScanInfo) {
	backBtn := widget.NewButton("Volver a Filtros", func() {
		showFilterDialog(myWindow, logger, scan, db)
	})

	compareBtn := widget.NewButton("Comparar 2 Escaneos", func() {
		if len(scans) < 2 {
			logger.Warn("Necesitas al menos 2 resultados para comparar")
			return
		}
		logger.Info("Iniciando comparación...")
		showCompareSelection(myWindow, logger, scan, db, scans)
	})

	if len(scans) == 0 {
		content := container.NewVBox(
			widget.NewLabel("No se encontraron resultados"),
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
			widget.NewLabel(fmt.Sprintf("Resultados Filtrados (%d encontrados)", len(scans))),
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

func showExploitSuggestions(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database, result *models.ScanResult) {
	// Conectar a Metasploit
	msfClient := msf.NewClient("127.0.0.1", 55553, "mypassword123")
	
	statusLabel := widget.NewLabel("Conectando a Metasploit...")
	progressBar := widget.NewProgressBarInfinite()
	
	backBtn := widget.NewButton("Volver al Historial", func() {
		logger.Info("Volviendo al detalle del escaneo...")
		showScanHistory(myWindow, logger, scan, db)
	})
	
	content := container.NewVBox(statusLabel, progressBar, widget.NewSeparator(), backBtn)
	myWindow.SetContent(content)

	go func() {
		// Login
		if err := msfClient.Login(); err != nil {
			logger.Errorf("Error conectando a Metasploit: %v", err)
			errorMsg := fmt.Sprintf("Error: %v\n\n¿Está msfrpcd corriendo?\nEjecuta: msfrpcd -P mypassword123 -S -a 127.0.0.1 -p 55553", err)
			
			statusLabel.SetText(errorMsg)
			progressBar.Hide()
			myWindow.SetContent(container.NewVBox(
				statusLabel,
				widget.NewSeparator(),
				widget.NewButton("Volver al Historial", func() {
					showScanHistory(myWindow, logger, scan, db)
				}),
			))
			return
		}

		logger.Info("Conectado a Metasploit, buscando exploits...")
		statusLabel.SetText("Buscando exploits sugeridos... (esto puede tardar)")

		// Sugerir exploits
		suggestions, err := msf.SuggestExploits(msfClient, result)
		if err != nil {
			logger.Errorf("Error sugiriendo exploits: %v", err)
			statusLabel.SetText(fmt.Sprintf("Error: %v", err))
			progressBar.Hide()
			return
		}

		if len(suggestions) == 0 {
			statusLabel.SetText("No se encontraron exploits sugeridos para los servicios detectados")
			progressBar.Hide()
			myWindow.SetContent(container.NewVBox(
				statusLabel,
				widget.NewSeparator(),
				widget.NewButton("Volver al Historial", func() {
					showScanHistory(myWindow, logger, scan, db)
				}),
			))
			return
		}

		logger.Infof("Se encontraron %d exploits sugeridos", len(suggestions))
		showExploitList(myWindow, logger, scan, db, result, suggestions, msfClient)
	}()
}

func showExploitList(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database, result *models.ScanResult, suggestions []msf.ExploitSuggestion, msfClient *msf.Client) {
	items := container.NewVBox()

	for _, s := range suggestions {
		suggestion := s
		exploitInfo := fmt.Sprintf("%s\nTarget: %s:%d (%s)\nRank: %s",
			suggestion.ModuleName,
			suggestion.Target,
			suggestion.Port,
			suggestion.Service,
			suggestion.Rank,
		)

		exploitBtn := widget.NewButton(exploitInfo, func() {
			showExploitOptions(myWindow, logger, scan, db, result, suggestion, msfClient)
		})
		items.Add(exploitBtn)
		items.Add(widget.NewSeparator())
	}

	backBtn := widget.NewButton("Volver al Historial", func() {
		showScanHistory(myWindow, logger, scan, db)
	})

	scroll := container.NewScroll(items)
	scroll.SetMinSize(fyne.NewSize(700, 400))

	content := container.NewBorder(
		container.NewVBox(
			widget.NewLabel(fmt.Sprintf("Exploits Sugeridos (%d encontrados)", len(suggestions))),
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
	myWindow.Resize(fyne.NewSize(800, 600))
}

func showExploitOptions(myWindow fyne.Window, logger *logrus.Logger, scan *scanner.Scanner, db *storage.Database, result *models.ScanResult, suggestion msf.ExploitSuggestion, msfClient *msf.Client) {
	lhostEntry := widget.NewEntry()
	lhostEntry.SetPlaceHolder("Tu IP (LHOST)")
	lhostEntry.SetText("0.0.0.0")

	lportEntry := widget.NewEntry()
	lportEntry.SetPlaceHolder("Puerto local (LPORT)")
	lportEntry.SetText("4444")

	executeBtn := widget.NewButton("⚠️ EJECUTAR EXPLOIT ⚠️", func() {
		lhost := lhostEntry.Text
		lport := 4444
		fmt.Sscanf(lportEntry.Text, "%d", &lport)

		logger.Warnf("Ejecutando exploit: %s contra %s:%d", suggestion.ModuleName, suggestion.Target, suggestion.Port)

		go func() {
			resultMsg, err := msf.ExecuteExploit(msfClient, suggestion, lhost, lport)
			if err != nil {
				logger.Errorf("Error ejecutando exploit: %v", err)
				return
			}
			logger.Infof("Resultado: %s", resultMsg)
		}()
	})
	executeBtn.Importance = widget.DangerImportance

	backBtn := widget.NewButton("Volver al Historial", func() {
		logger.Info("Volviendo a lista de exploits...")
		showExploitSuggestions(myWindow, logger, scan, db, result)
	})
	

	info := widget.NewLabel(fmt.Sprintf(
		"Exploit: %s\n\nTarget: %s:%d\nServicio: %s\nRank: %s\n\nDescripción: %s",
		suggestion.ModuleName,
		suggestion.Target,
		suggestion.Port,
		suggestion.Service,
		suggestion.Rank,
		suggestion.Description,
	))
	info.Wrapping = fyne.TextWrapWord

	warning := widget.NewLabel("⚠️ ADVERTENCIA: Solo ejecuta esto en sistemas que tengas permiso para atacar")
	warning.Importance = widget.DangerImportance

	form := container.NewVBox(
		widget.NewLabel("Opciones del Exploit"),
		widget.NewSeparator(),
		info,
		widget.NewSeparator(),
		widget.NewLabel("LHOST (tu IP):"),
		lhostEntry,
		widget.NewLabel("LPORT (tu puerto):"),
		lportEntry,
		widget.NewSeparator(),
		warning,
		widget.NewSeparator(),
		container.NewHBox(executeBtn, backBtn),
	)

	scroll := container.NewScroll(form)
	myWindow.SetContent(scroll)
	myWindow.Resize(fyne.NewSize(700, 600))
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

// Tema cyberpunk/hacker inspirado en Bjorn
type cyberpunkTheme struct{}

func (c *cyberpunkTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.RGBA{10, 10, 10, 255}
	case theme.ColorNameForeground:
		return color.RGBA{57, 255, 20, 255}
	case theme.ColorNamePrimary:
		return color.RGBA{0, 255, 255, 255}
	case theme.ColorNameButton:
		return color.RGBA{0, 100, 0, 255}
	case theme.ColorNameInputBackground:
		return color.RGBA{20, 20, 20, 255}
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (c *cyberpunkTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

func (c *cyberpunkTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (c *cyberpunkTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}
