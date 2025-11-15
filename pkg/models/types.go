package models

import "time"

// ScanResult resultado del escaneo
type ScanResult struct {
	ID          string          `json:"id"`
	Timestamp   time.Time       `json:"timestamp"`
	Target      string          `json:"target"`
	StartTime   time.Time       `json:"start_time"`
	EndTime     time.Time       `json:"end_time"`
	TotalHosts  int             `json:"total_hosts"`
	Hosts       []Host          `json:"hosts"`
	Vulnerables []Vulnerability `json:"vulnerabilities"`
	StatusCode  int             `json:"status_code"`
	ErrorMsg    string          `json:"error_message,omitempty"`
}

// Host información de host
type Host struct {
	ID         string    `json:"id"`
	IP         string    `json:"ip"`
	Hostname   string    `json:"hostname"`
	Status     string    `json:"status"`
	OS         string    `json:"os"`
	Ports      []Port    `json:"ports"`
	Services   []Service `json:"services"`
	Vulnerable bool      `json:"vulnerable"`
	Risk       string    `json:"risk"`
}

// Port información de puerto
type Port struct {
	ID       int    `json:"id"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version"`
}

// Service información de servicio
type Service struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Product   string   `json:"product"`
	Extrainfo string   `json:"extrainfo"`
	CPEs      []string `json:"cpes"`
}

// Vulnerability información de vulnerabilidad
type Vulnerability struct {
	HostIP      string   `json:"host_ip"`
	Port        int      `json:"port"`
	Service     string   `json:"service"`
	CVE         []string `json:"cve"`
	CWE         string   `json:"cwe"`
	OWASP       string   `json:"owasp"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
}

// ExploitResult resultado de exploit
type ExploitResult struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Module    string    `json:"module"`
	Target    string    `json:"target"`
	Success   bool      `json:"success"`
	SessionID string    `json:"session_id"`
	Output    string    `json:"output"`
}

// ScanOptions opciones para ejecutar un escaneo
type ScanOptions struct {
	Target         string   `json:"target"`
	Ports          string   `json:"ports"`
	Aggressive     bool     `json:"aggressive"`
	OSDetection    bool     `json:"os_detection"`
	ServiceVersion bool     `json:"service_version"`
	NSEScripts     []string `json:"nse_scripts,omitempty"`
	Timeout        int      `json:"timeout"`
}
