package scanner

import (
	"context"
	"fmt"
	"time"
	"github.com/Ullaakut/nmap/v3"
)

type ScanOptions struct {
	Ports      []string
	NSEScripts []string
	Aggressive bool
}

type Host struct {
	IP       string
	Hostname string
	Status   string
	Ports    []Port
	Services []Service
	OS       string
}

type Port struct {
	ID       int
	Protocol string
	State    string
	Service  string
	Version  string
}

type Service struct {
	Name    string
	Version string
	CPE     []string
}

type ScanResult struct {
	Hosts      []Host
	StartTime  time.Time
	EndTime    time.Time
	TotalHosts int
}

// NetworkScanner gestiona escaneos de red
func ScanNetwork(ctx context.Context, target string, options ScanOptions) (*ScanResult, error) {
	// Configurar scanner Nmap
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts(options.Ports...),
		nmap.WithServiceInfo(),
		nmap.WithOSDetection(),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithScripts(options.NSEScripts...),
	)

	if err != nil {
		return nil, fmt.Errorf("error creando scanner: %w", err)
	}
	startTime := time.Now()
	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("error en escaneo: %w", err)
	}
	if warnings != nil {
		fmt.Printf("Advertencias: %v\n", warnings)
	}
	// Parsear resultados
	scanResult := &ScanResult{
		StartTime:  startTime,
		EndTime:    time.Now(),
		TotalHosts: len(result.Hosts),
		Hosts:      []Host{},
	}
	for _, host := range result.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}
		h := Host{
			IP:      host.Addresses[0].Addr,
			Status:  string(host.Status.State),
			Ports:   []Port{},
			Services: []Service{},
		}
		if len(host.Hostnames) > 0 {
			h.Hostname = host.Hostnames[0].Name
		}
		if len(host.OS.Matches) > 0 {
			h.OS = host.OS.Matches[0].Name
		}
		for _, port := range host.Ports {
			p := Port{
				ID:       int(port.ID),
				Protocol: port.Protocol,
				State:    string(port.State.State),
				Service:  port.Service.Name,
				Version:  port.Service.Version,
			}
			h.Ports = append(h.Ports, p)
			if port.Service.Name != "" {
				svc := Service{
					Name:    port.Service.Name,
					Version: port.Service.Version,
				}
				for _, cpe := range port.Service.CPEs {
					svc.CPE = append(svc.CPE, string(cpe))
				}
				h.Services = append(h.Services, svc)
			}
		}
		scanResult.Hosts = append(scanResult.Hosts, h)
	}
	return scanResult, nil
}

// DefaultScanOptions retorna opciones predeterminadas
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		Ports: []string{"21", "22", "23", "25", "80", "443", "3306", "3389", "8080"},
		NSEScripts: []string{"vuln", "exploit", "http-enum", "http-vuln-*", "ssl-*", "smb-vuln-*"},
		Aggressive: false,
	}
}
