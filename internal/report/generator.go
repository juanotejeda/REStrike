package report

import (
	"fmt"
	"os"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/juanotejeda/REStrike/pkg/models"
)

// Generator generador de reportes
type Generator struct {
	logger Logger
}

// Logger interface
type Logger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// NewGenerator crea nuevo generador
func NewGenerator(logger Logger) *Generator {
	return &Generator{logger: logger}
}

// GeneratePDF genera reporte en PDF
func (g *Generator) GeneratePDF(result *models.ScanResult, filename string) error {
	g.logger.Infof("Generando reporte PDF: %s", filename)

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	// Título
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "REStrike - Reporte de Escaneo")
	pdf.Ln(15)

	// Información general
	pdf.SetFont("Arial", "", 11)
	pdf.Cell(0, 10, fmt.Sprintf("Target: %s", result.Target))
	pdf.Ln(7)
	pdf.Cell(0, 10, fmt.Sprintf("Fecha: %s", result.StartTime.Format("2006-01-02 15:04:05")))
	pdf.Ln(7)
	pdf.Cell(0, 10, fmt.Sprintf("Hosts encontrados: %d", result.TotalHosts))
	pdf.Ln(7)
	pdf.Cell(0, 10, fmt.Sprintf("Vulnerabilidades: %d", len(result.Vulnerables)))
	pdf.Ln(15)

	// Hosts
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 10, "Hosts Escaneados")
	pdf.Ln(10)

	pdf.SetFont("Arial", "", 10)
	for _, host := range result.Hosts {
		pdf.Cell(0, 8, fmt.Sprintf("IP: %s - Estado: %s - Puertos: %d", host.IP, host.Status, len(host.Ports)))
		pdf.Ln(6)
	}

	// Vulnerabilidades
	if len(result.Vulnerables) > 0 {
		pdf.Ln(10)
		pdf.SetFont("Arial", "B", 12)
		pdf.Cell(0, 10, "Vulnerabilidades Detectadas")
		pdf.Ln(10)

		pdf.SetFont("Arial", "", 9)
		for _, vuln := range result.Vulnerables {
			pdf.MultiCell(0, 6, fmt.Sprintf("Host: %s:%d - %s - Severidad: %s - OWASP: %s",
				vuln.HostIP, vuln.Port, vuln.Service, vuln.Severity, vuln.OWASP), "", "", false)
			pdf.Ln(3)
		}
	}

	// Guardar
	err := pdf.OutputFileAndClose(filename)
	if err != nil {
		g.logger.Errorf("Error generando PDF: %v", err)
		return err
	}

	g.logger.Infof("Reporte generado exitosamente: %s", filename)
	return nil
}

// GenerateHTML genera reporte en HTML
func (g *Generator) GenerateHTML(result *models.ScanResult, filename string) error {
	g.logger.Infof("Generando reporte HTML: %s", filename)

	html := `
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>REStrike Reporte</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 20px; }
		h1 { color: #333; }
		.section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
		.host { background: #f9f9f9; padding: 10px; margin: 5px 0; }
		.critical { color: red; }
		.high { color: orange; }
		table { width: 100%; border-collapse: collapse; }
		th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
		th { background-color: #f2f2f2; }
	</style>
</head>
<body>
	<h1>REStrike - Reporte de Escaneo</h1>
	<div class="section">
		<h2>Información General</h2>
		<p><strong>Target:</strong> ` + result.Target + `</p>
		<p><strong>Fecha:</strong> ` + result.StartTime.Format("2006-01-02 15:04:05") + `</p>
		<p><strong>Hosts encontrados:</strong> ` + fmt.Sprintf("%d", result.TotalHosts) + `</p>
		<p><strong>Vulnerabilidades:</strong> ` + fmt.Sprintf("%d", len(result.Vulnerables)) + `</p>
	</div>
	<div class="section">
		<h2>Hosts Escaneados</h2>
		<table>
			<tr><th>IP</th><th>Hostname</th><th>Estado</th><th>SO</th><th>Puertos</th></tr>
`

	for _, host := range result.Hosts {
		html += fmt.Sprintf(`
			<tr>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%d</td>
			</tr>
`, host.IP, host.Hostname, host.Status, host.OS, len(host.Ports))
	}

	html += `
		</table>
	</div>
`

	if len(result.Vulnerables) > 0 {
		html += `
	<div class="section">
		<h2>Vulnerabilidades</h2>
		<table>
			<tr><th>Host</th><th>Puerto</th><th>Serv

