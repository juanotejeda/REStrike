package comparison

import (
	"fmt"

	"github.com/juanotejeda/REStrike/pkg/models"
)

// ComparisonResult resultado de comparación entre dos escaneos
type ComparisonResult struct {
	Scan1        *models.ScanResult
	Scan2        *models.ScanResult
	NewHosts     []string
	RemovedHosts []string
	NewPorts     []PortChange
	ClosedPorts  []PortChange
	Summary      string
}

// PortChange representa un cambio en puertos
type PortChange struct {
	Host     string
	Port     int
	Protocol string
	Service  string
	Action   string // "opened" o "closed"
}

// CompareScanResults compara dos resultados de escaneo
func CompareScanResults(older, newer *models.ScanResult) *ComparisonResult {
	result := &ComparisonResult{
		Scan1: older,
		Scan2: newer,
	}

	// Mapear hosts del escaneo antiguo
	oldHosts := make(map[string]*models.Host)
	for _, host := range older.Hosts {
		oldHosts[host.IP] = &host
	}

	// Mapear hosts del escaneo nuevo
	newHosts := make(map[string]*models.Host)
	for _, host := range newer.Hosts {
		newHosts[host.IP] = &host
	}

	// Detectar hosts nuevos y removidos
	for ip := range newHosts {
		if _, exists := oldHosts[ip]; !exists {
			result.NewHosts = append(result.NewHosts, ip)
		}
	}

	for ip := range oldHosts {
		if _, exists := newHosts[ip]; !exists {
			result.RemovedHosts = append(result.RemovedHosts, ip)
		}
	}

	// Comparar puertos en hosts que existen en ambos
	for ip, newHost := range newHosts {
		if oldHost, exists := oldHosts[ip]; exists {
			// Mapear puertos antiguos
			oldPorts := make(map[string]models.Port)
			for _, port := range oldHost.Ports {
				key := fmt.Sprintf("%d-%s", port.ID, port.Protocol)
				oldPorts[key] = port
			}

			// Mapear puertos nuevos
			newPorts := make(map[string]models.Port)
			for _, port := range newHost.Ports {
				key := fmt.Sprintf("%d-%s", port.ID, port.Protocol)
				newPorts[key] = port
			}

			// Detectar puertos nuevos
			for key, port := range newPorts {
				if _, exists := oldPorts[key]; !exists {
					result.NewPorts = append(result.NewPorts, PortChange{
						Host:     ip,
						Port:     port.ID,
						Protocol: port.Protocol,
						Service:  port.Service,
						Action:   "opened",
					})
				}
			}

			// Detectar puertos cerrados
			for key, port := range oldPorts {
				if _, exists := newPorts[key]; !exists {
					result.ClosedPorts = append(result.ClosedPorts, PortChange{
						Host:     ip,
						Port:     port.ID,
						Protocol: port.Protocol,
						Service:  port.Service,
						Action:   "closed",
					})
				}
			}
		}
	}

	// Generar resumen
	result.Summary = generateSummary(result)

	return result
}

func generateSummary(result *ComparisonResult) string {
	summary := fmt.Sprintf("COMPARACIÓN DE ESCANEOS\n\n")
	summary += fmt.Sprintf("Escaneo 1: %s (%s)\n", result.Scan1.Target, result.Scan1.StartTime.Format("2006-01-02 15:04"))
	summary += fmt.Sprintf("Escaneo 2: %s (%s)\n\n", result.Scan2.Target, result.Scan2.StartTime.Format("2006-01-02 15:04"))

	duration := result.Scan2.StartTime.Sub(result.Scan1.StartTime)
	summary += fmt.Sprintf("Tiempo transcurrido: %v\n\n", duration)

	summary += "═══════════════════════════════════════\n\n"

	// Hosts nuevos
	if len(result.NewHosts) > 0 {
		summary += fmt.Sprintf("✅ HOSTS NUEVOS (%d):\n", len(result.NewHosts))
		for _, host := range result.NewHosts {
			summary += fmt.Sprintf("  + %s\n", host)
		}
		summary += "\n"
	}

	// Hosts removidos
	if len(result.RemovedHosts) > 0 {
		summary += fmt.Sprintf("❌ HOSTS REMOVIDOS (%d):\n", len(result.RemovedHosts))
		for _, host := range result.RemovedHosts {
			summary += fmt.Sprintf("  - %s\n", host)
		}
		summary += "\n"
	}

	// Puertos nuevos
	if len(result.NewPorts) > 0 {
		summary += fmt.Sprintf("🟢 PUERTOS ABIERTOS (%d):\n", len(result.NewPorts))
		for _, port := range result.NewPorts {
			summary += fmt.Sprintf("  + %s:%d/%s [%s]\n", port.Host, port.Port, port.Protocol, port.Service)
		}
		summary += "\n"
	}

	// Puertos cerrados
	if len(result.ClosedPorts) > 0 {
		summary += fmt.Sprintf("🔴 PUERTOS CERRADOS (%d):\n", len(result.ClosedPorts))
		for _, port := range result.ClosedPorts {
			summary += fmt.Sprintf("  - %s:%d/%s [%s]\n", port.Host, port.Port, port.Protocol, port.Service)
		}
		summary += "\n"
	}

	if len(result.NewHosts) == 0 && len(result.RemovedHosts) == 0 &&
		len(result.NewPorts) == 0 && len(result.ClosedPorts) == 0 {
		summary += "No se detectaron cambios.\n"
	}

	return summary
}

