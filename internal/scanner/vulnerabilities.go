package scanner

// VulnerabilityRule define una regla de vulnerabilidad
type VulnerabilityRule struct {
	Port     int
	Protocol string
	Service  string
	Risk     string // critical, high, medium, low
	Description string
}

// VulnerabilityRules base de datos de reglas
var VulnerabilityRules = []VulnerabilityRule{
	{Port: 22, Protocol: "tcp", Service: "ssh", Risk: "high", Description: "SSH - Acceso remoto. Usar claves en lugar de contraseñas"},
	{Port: 3306, Protocol: "tcp", Service: "mysql", Risk: "critical", Description: "MySQL - Base de datos expuesta. DEBE estar restringido"},
	{Port: 5432, Protocol: "tcp", Service: "postgresql", Risk: "critical", Description: "PostgreSQL - Base de datos expuesta. DEBE estar restringido"},
	{Port: 27017, Protocol: "tcp", Service: "mongodb", Risk: "critical", Description: "MongoDB - Base de datos sin autenticación por defecto"},
	{Port: 6379, Protocol: "tcp", Service: "redis", Risk: "critical", Description: "Redis - Cache sin autenticación. Datos expuestos"},
	{Port: 5984, Protocol: "tcp", Service: "couchdb", Risk: "critical", Description: "CouchDB - Base de datos expuesta"},
	{Port: 9200, Protocol: "tcp", Service: "elasticsearch", Risk: "critical", Description: "Elasticsearch - Búsqueda expuesta. Datos sensibles en riesgo"},
	{Port: 8080, Protocol: "tcp", Service: "http-proxy", Risk: "high", Description: "HTTP Proxy - Servicio web alternativo"},
	{Port: 3389, Protocol: "tcp", Service: "rdp", Risk: "high", Description: "RDP - Acceso remoto Windows. Fuerte objetivo de ataques"},
	{Port: 139, Protocol: "tcp", Service: "netbios", Risk: "high", Description: "NetBIOS - Compartición de archivos Windows"},
	{Port: 445, Protocol: "tcp", Service: "smb", Risk: "high", Description: "SMB - Compartición de archivos. Riesgo de ransomware"},
	{Port: 21, Protocol: "tcp", Service: "ftp", Risk: "high", Description: "FTP - Transferencia sin cifrado. Usar SFTP"},
	{Port: 23, Protocol: "tcp", Service: "telnet", Risk: "critical", Description: "Telnet - Conexión sin cifrado. OBSOLETO y peligroso"},
	{Port: 25, Protocol: "tcp", Service: "smtp", Risk: "medium", Description: "SMTP - Servidor de correo. Validar autenticación"},
	{Port: 53, Protocol: "tcp", Service: "dns", Risk: "medium", Description: "DNS - Servicio de nombres. Verificar zone transfer"},
	{Port: 111, Protocol: "tcp", Service: "rpcbind", Risk: "high", Description: "RPC - Remote Procedure Call. Información sensible expuesta"},
	{Port: 161, Protocol: "udp", Service: "snmp", Risk: "high", Description: "SNMP - Gestión de red. Default credentials comunes"},
	{Port: 389, Protocol: "tcp", Service: "ldap", Risk: "medium", Description: "LDAP - Directorio. Verificar enumeración de usuarios"},
	{Port: 8443, Protocol: "tcp", Service: "https", Risk: "medium", Description: "HTTPS alternativo - Verificar certificado SSL"},
	{Port: 9000, Protocol: "tcp", Service: "fastcgi", Risk: "high", Description: "FastCGI - Interfaz web. Riesgo de ejecución remota"},
}

// GetVulnerabilitiesForPort obtiene vulnerabilidades de un puerto
func GetVulnerabilitiesForPort(port int, protocol, service string) []VulnerabilityRule {
	var matches []VulnerabilityRule
	for _, rule := range VulnerabilityRules {
		if rule.Port == port {
			matches = append(matches, rule)
		}
	}
	return matches
}

// RiskLevel retorna emoji y color del riesgo
func RiskLevel(risk string) string {
	switch risk {
	case "critical":
		return "🔴 CRÍTICO"
	case "high":
		return "🟠 ALTO"
	case "medium":
		return "🟡 MEDIO"
	case "low":
		return "🟢 BAJO"
	default:
		return "⚪ DESCONOCIDO"
	}
}
