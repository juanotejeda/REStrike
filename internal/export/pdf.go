package export

import (
	"fmt"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/juanotejeda/REStrike/pkg/models"
)

// ExportToPDF genera reporte en PDF
func ExportToPDF(filename string, result *models.ScanResult) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 20)
	pdf.Cell(0, 10, "REStrike - Reporte de Escaneo")
	pdf.Ln(15)

	pdf.SetFont("Arial", "", 10)
	pdf.Cell(0, 5, fmt.Sprintf("Generado: %s", time.Now().Format("2006-01-02 15:04:05")))
	pdf.Ln(10)

	// Información general
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 7, "Información General")
	pdf.Ln(7)

	pdf.SetFont("Arial", "", 10)
	pdf.Cell(0, 6, fmt.Sprintf("Target: %s", result.Target))
	pdf.Ln(6)

	pdf.Cell(0, 6, fmt.Sprintf("Fecha Inicio: %s", result.StartTime.Format("2006-01-02 15:04:05")))
	pdf.Ln(6)

	pdf.Cell(0, 6, fmt.Sprintf("Fecha Fin: %s", result.EndTime.Format("2006-01-02 15:04:05")))
	pdf.Ln(6)

	duration := result.EndTime.Sub(result.StartTime)
	pdf.Cell(0, 6, fmt.Sprintf("Duración: %v", duration))
	pdf.Ln(6)

	pdf.Cell(0, 6, fmt.Sprintf("Hosts: %d", result.TotalHosts))
	pdf.Ln(10)

	// Hosts descubiertos
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 7, "Hosts Descubiertos")
	pdf.Ln(7)

	pdf.SetFont("Arial", "", 9)

	if len(result.Hosts) > 0 {
		for _, host := range result.Hosts {
			pdf.SetFont("Arial", "B", 10)
			pdf.Cell(0, 6, fmt.Sprintf("IP: %s", host.IP))
			pdf.Ln(6)

			pdf.SetFont("Arial", "", 9)
			if host.Hostname != "" {
				pdf.Cell(0, 5, fmt.Sprintf("  Hostname: %s", host.Hostname))
				pdf.Ln(5)
			}

			pdf.Cell(0, 5, fmt.Sprintf("  Estado: %s", host.Status))
			pdf.Ln(5)

			if host.OS != "" {
				pdf.Cell(0, 5, fmt.Sprintf("  SO: %s", host.OS))
				pdf.Ln(5)
			}

			// Puertos
			if len(host.Ports) > 0 {
				pdf.Cell(0, 5, "  Puertos Abiertos:")
				pdf.Ln(5)

				for _, port := range host.Ports {
					service := port.Service
					if port.Version != "" {
						service = fmt.Sprintf("%s (%s)", port.Service, port.Version)
					}

					portStr := fmt.Sprintf("    • %d/%s: %s [%s]", port.ID, port.Protocol, port.State, service)
					pdf.Cell(0, 5, portStr)
					pdf.Ln(5)
				}
			}

			pdf.Ln(3)
		}
	} else {
		pdf.Cell(0, 6, "No se encontraron hosts activos")
		pdf.Ln(6)
	}

	// Footer
	pdf.SetFont("Arial", "I", 8)
	pdf.Ln(5)
	pdf.Cell(0, 10, "REStrike v0.1.0 - Herramienta de Pentesting")

	return pdf.OutputFileAndClose(filename)
}
