package export

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/juanotejeda/REStrike/pkg/models"
)

// ExportToCSV exporta resultado a CSV
func ExportToCSV(filename string, result *models.ScanResult) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Header
	header := []string{"IP", "Hostname", "Estado", "OS", "Puerto", "Protocolo", "Estado Puerto", "Servicio", "Versión"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Datos
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 {
			// Host sin puertos
			row := []string{
				host.IP,
				host.Hostname,
				host.Status,
				host.OS,
				"N/A",
				"N/A",
				"N/A",
				"N/A",
				"N/A",
			}
			if err := writer.Write(row); err != nil {
				return err
			}
		} else {
			// Host con puertos
			for _, port := range host.Ports {
				row := []string{
					host.IP,
					host.Hostname,
					host.Status,
					host.OS,
					fmt.Sprintf("%d", port.ID),
					port.Protocol,
					port.State,
					port.Service,
					port.Version,
				}
				if err := writer.Write(row); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
