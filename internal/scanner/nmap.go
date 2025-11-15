package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/juanotejeda/REStrike/pkg/models"
)

// Scanner gestor de escaneos Nmap
type Scanner struct {
	logger Logger
}

// Logger interface
type Logger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
}

// NewScanner crea nuevo scanner
func NewScanner(logger Logger) *Scanner {
	return &Scanner{logger: logger}
}

// CheckNmapAvailability verifica si Nmap está disponible
func (s *Scanner) CheckNmapAvailability() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// ScanNetwork ejecuta escaneo de red
func (s *Scanner) ScanNetwork(ctx context.Context, target string) (*models.ScanResult, error) {
	s.logger.Infof("Iniciando escaneo de: %s", target)

	// Verificar que Nmap esté disponible
	if !s.CheckNmapAvailability() {
		s.logger.Errorf("Nmap no está instalado o no se encuentra en PATH")
		return nil, fmt.Errorf("nmap no disponible")
	}

	result := &models.ScanResult{
		Target:    target,
		StartTime: time.Now(),
		Hosts:     []models.Host{},
	}

	// Configurar scanner Nmap - sin OS detection para evitar requerir sudo
	// El usuario puede ejecutar con sudo si necesita features avanzadas
	opts := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithPorts("1-1000"),
		nmap.WithServiceInfo(),
		nmap.WithTimingTemplate(nmap.TimingPolite),
	}

	// Si estamos ejecutando como root, habilitar OS detection
	if os.Geteuid() == 0 {
		s.logger.Infof("Ejecutando como root - habilitando detección de SO")
		opts = append(opts, nmap.WithOSDetection())
	} else {
		s.logger.Warnf("No ejecutando como root - omitiendo detección de SO (usa 'sudo' para habilitarlo)")
	}

	scanner, err := nmap.NewScanner(ctx, opts...)
	if err != nil {
		s.logger.Errorf("Error creando scanner: %v", err)
		return nil, fmt.Errorf("error creando scanner: %w", err)
	}

	// Ejecutar escaneo
	res, warnings, err := scanner.Run()
	if err != nil {
		s.logger.Errorf("Error en escaneo: %v", err)
		return nil, fmt.Errorf("error en escaneo: %w", err)
	}

	if warnings != nil {
		s.logger.Infof("Advertencias: %v", warnings)
	}

	// Procesar resultados
	for _, host := range res.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}

		h := models.Host{
			IP:     host.Addresses[0].Addr,
			Status: string(host.Status.State),
			Ports:  []models.Port{},
		}

		// Hostname
		if len(host.Hostnames) > 0 {
			h.Hostname = host.Hostnames[0].Name
		}

		// SO (solo si se detectó)
		if len(host.OS.Matches) > 0 {
			h.OS = host.OS.Matches[0].Name
		}

		// Puertos
		for _, port := range host.Ports {
			p := models.Port{
				ID:       int(port.ID),
				Protocol: port.Protocol,
				State:    string(port.State.State),
				Service:  port.Service.Name,
				Version:  port.Service.Version,
			}
			h.Ports = append(h.Ports, p)
		}

		result.Hosts = append(result.Hosts, h)
	}

	result.EndTime = time.Now()
	result.TotalHosts = len(result.Hosts)
	result.StatusCode = 2 // completed

	s.logger.Infof("Escaneo completado: %d hosts encontrados", result.TotalHosts)
	return result, nil
}
