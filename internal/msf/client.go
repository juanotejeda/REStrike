package msf

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/juanotejeda/REStrike/pkg/models"
)

// ---------------------
// Tipos y helpers
// ---------------------

// Client cliente para Metasploit que lee desde archivos JSON
type Client struct {
	MetadataPath string
	ExploitCache map[string]interface{}
}

// HostContext contexto simplificado del host/servicio
type HostContext struct {
	OS      string
	Service string
	Port    int
}

func buildHostContext(host models.Host, port models.Port) HostContext {
	return HostContext{
		OS:      strings.ToLower(host.OS),
		Service: strings.ToLower(port.Service),
		Port:    port.ID,
	}
}

// Lista negra básica de módulos muy específicos que suelen ser ruido en labs genéricos
var moduleNameBlacklist = []string{
	"adobe_flash",
	"ivanti_",
	"nagios_",
	"accellion_",
	"qnap_",
}

// matchPlatform decide si un módulo tiene sentido para el contexto del host
func matchPlatform(ctx HostContext, moduleName string) bool {
	lower := strings.ToLower(moduleName)

	// Filtro por blacklist genérica
	for _, bad := range moduleNameBlacklist {
		if strings.Contains(lower, bad) {
			return false
		}
	}

	// Filtro heurístico por SO detectado
	if ctx.OS != "" {
		isWinHost := strings.Contains(ctx.OS, "windows")
		isNixHost := strings.Contains(ctx.OS, "linux") || strings.Contains(ctx.OS, "unix")

		isWinModule := strings.Contains(lower, "windows/")
		isNixModule := strings.Contains(lower, "linux/") || strings.Contains(lower, "unix/")

		if isWinHost && isNixModule {
			return false
		}
		if isNixHost && isWinModule {
			return false
		}
	}

	return true
}

// ExploitSuggestion sugerencia de exploit
type ExploitSuggestion struct {
	ModuleName  string
	Description string
	Rank        string
	Target      string
	Port        int
	Service     string
}

// rankOrder asigna prioridad numérica a cada rank
func rankOrder(rank string) int {
	switch strings.ToLower(rank) {
	case "excellent":
		return 1
	case "great":
		return 2
	case "good":
		return 3
	case "normal":
		return 4
	case "average":
		return 5
	case "low":
		return 6
	case "manual":
		return 7
	default:
		return 8
	}
}

// ---------------------
// Cliente Metasploit JSON
// ---------------------

// NewClient crea un nuevo cliente Metasploit
func NewClient(host string, port int, password string) *Client {
	msfPath := filepath.Join(os.Getenv("HOME"), ".msf4", "store", "modules_metadata.json")

	return &Client{
		MetadataPath: msfPath,
		ExploitCache: make(map[string]interface{}),
	}
}

// Login verifica que el archivo existe
func (c *Client) Login() error {
	fmt.Println("[*] Leyendo metadatos de Metasploit desde", c.MetadataPath)

	if _, err := os.Stat(c.MetadataPath); err != nil {
		return fmt.Errorf("archivo de metadatos no encontrado: %s", c.MetadataPath)
	}

	return nil
}

// ListExploits lista todos los módulos exploit disponibles
func (c *Client) ListExploits() ([]string, error) {
	data, err := ioutil.ReadFile(c.MetadataPath)
	if err != nil {
		return nil, fmt.Errorf("error leyendo metadatos: %w", err)
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("error parseando JSON: %w", err)
	}

	var exploits []string

	// Claves tipo "exploit/windows/..." o "exploit/linux/..."
	for path := range metadata {
		if strings.HasPrefix(path, "exploit_") || strings.HasPrefix(path, "exploit/") {
			exploits = append(exploits, path)
		}
	}

	fmt.Printf("[DEBUG] Total exploits encontrados: %d\n", len(exploits))
	return exploits, nil
}

// GetExploits busca exploits por servicio/puerto (filtro básico por nombre)
func (c *Client) GetExploits(service string, port int) ([]map[string]interface{}, error) {
	fmt.Printf("[DEBUG] Buscando exploits para servicio: %s, puerto: %d\n", service, port)

	allModules, err := c.ListExploits()
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadFile(c.MetadataPath)
	if err != nil {
		return nil, fmt.Errorf("error leyendo metadatos: %w", err)
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("error parseando JSON: %w", err)
	}

	var exploits []map[string]interface{}
	serviceLower := strings.ToLower(service)

	matchCount := 0
	for _, modulePath := range allModules {
		if len(exploits) >= 10 {
			break
		}

		pathLower := strings.ToLower(modulePath)

		// Reglas de match más estrictas:
		// - Para http, solo módulos claramente HTTP/web
		if serviceLower == "http" || serviceLower == "https" {
			if !strings.Contains(pathLower, "/http/") &&
				!strings.HasPrefix(pathLower, "exploit_multi/http") &&
				!strings.HasPrefix(pathLower, "exploit_linux/http") &&
				!strings.HasPrefix(pathLower, "exploit_windows/http") &&
				!strings.Contains(pathLower, "/webapp/") {
				continue
			}
		} else {
			// Para otros servicios, exigir que el nombre tenga el servicio como token
			if !strings.Contains(pathLower, "/"+serviceLower+"_") &&
				!strings.Contains(pathLower, "/"+serviceLower+"/") &&
				!strings.HasSuffix(pathLower, "_"+serviceLower) &&
				!strings.Contains(pathLower, "_"+serviceLower+"_") {
				continue
			}
		}

		moduleInfo, ok := metadata[modulePath].(map[string]interface{})
		if !ok {
			continue
		}

		matchCount++
		fmt.Printf("[DEBUG] Exploit encontrado (filtrado): %s\n", modulePath)
		exploits = append(exploits, map[string]interface{}{
			"name": modulePath,
			"info": moduleInfo,
		})
	}

	fmt.Printf("[DEBUG] Total matches para '%s': %d\n", service, matchCount)
	return exploits, nil
}

// SearchModules busca módulos por palabra clave
func (c *Client) SearchModules(query string) ([]string, error) {
	allModules, err := c.ListExploits()
	if err != nil {
		return nil, err
	}

	var results []string
	queryLower := strings.ToLower(query)

	for _, module := range allModules {
		if strings.Contains(strings.ToLower(module), queryLower) {
			results = append(results, module)
		}
	}

	return results, nil
}

// GetModuleInfo obtiene información de un módulo
func (c *Client) GetModuleInfo(moduleType, moduleName string) (map[string]interface{}, error) {
	data, err := ioutil.ReadFile(c.MetadataPath)
	if err != nil {
		return nil, err
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}

	if moduleInfo, ok := metadata[moduleName].(map[string]interface{}); ok {
		return moduleInfo, nil
	}

	return nil, fmt.Errorf("módulo no encontrado: %s", moduleName)
}

// ExecuteModule ejecuta un módulo exploit (simulado)
func (c *Client) ExecuteModule(moduleType, moduleName string, options map[string]string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"job_id": "job_placeholder",
		"status": "executed",
	}, nil
}

// ---------------------
// Sugerencias de exploits
// ---------------------

// SuggestExploits sugiere exploits basados en resultados de escaneo
func SuggestExploits(client *Client, result *models.ScanResult) ([]ExploitSuggestion, error) {
	var suggestions []ExploitSuggestion

	// Términos ya buscados para no repetir búsquedas
	searched := make(map[string]bool)
	// Módulos ya agregados para evitar duplicados
	seenModules := make(map[string]bool)
	// Contador por host:puerto:servicio
	perPortCount := make(map[string]int)

	const maxPerPort = 4      // máximo por (host,puerto,servicio)
	const maxSuggestions = 12 // máximo total mostrado en GUI

	fmt.Printf("[DEBUG] Analizando %d hosts para sugerir exploits\n", len(result.Hosts))

	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			if port.State != "open" {
				continue
			}

			ctx := buildHostContext(host, port)

			searchTerms := []string{
				port.Service,
				fmt.Sprintf("%s %d", port.Service, port.ID),
			}
			if port.Version != "" {
				searchTerms = append(searchTerms, fmt.Sprintf("%s %s", port.Service, port.Version))
			}

			for _, term := range searchTerms {
				if term == "" || searched[term] {
					continue
				}
				searched[term] = true

				exploits, err := client.GetExploits(term, port.ID)
				if err != nil {
					fmt.Printf("[DEBUG] Error buscando exploits para '%s': %v\n", term, err)
					continue
				}

				for _, ex := range exploits {
					name, ok := ex["name"].(string)
					if !ok || name == "" {
						continue
					}
					if seenModules[name] {
						continue
					}
					if !matchPlatform(ctx, name) {
						continue
					}

					key := fmt.Sprintf("%s:%d:%s", host.IP, port.ID, strings.ToLower(port.Service))
					if perPortCount[key] >= maxPerPort {
						continue
					}

					description := "N/A"
					rank := "unknown"
					if info, ok := ex["info"].(map[string]interface{}); ok {
						if desc, ok := info["description"].(string); ok && desc != "" {
							description = desc
						}
						if r, ok := info["rank"].(string); ok && r != "" {
							rank = r
						}
					}

					suggestions = append(suggestions, ExploitSuggestion{
						ModuleName:  name,
						Description: description,
						Rank:        rank,
						Target:      host.IP,
						Port:        port.ID,
						Service:     port.Service,
					})

					seenModules[name] = true
					perPortCount[key]++

					if len(suggestions) >= maxSuggestions {
						break
					}
				}
				if len(suggestions) >= maxSuggestions {
					break
				}
			}
			if len(suggestions) >= maxSuggestions {
				break
			}
		}
		if len(suggestions) >= maxSuggestions {
			break
		}
	}

	// Ordenar por rank y nombre
	sort.Slice(suggestions, func(i, j int) bool {
		ri := rankOrder(suggestions[i].Rank)
		rj := rankOrder(suggestions[j].Rank)
		if ri != rj {
			return ri < rj
		}
		return suggestions[i].ModuleName < suggestions[j].ModuleName
	})

	fmt.Printf("[DEBUG] Total sugerencias (tras filtros): %d\n", len(suggestions))
	return suggestions, nil
}

// ExecuteExploit ejecuta un exploit contra un target (simulado)
func ExecuteExploit(client *Client, suggestion ExploitSuggestion, lhost string, lport int) (string, error) {
	return fmt.Sprintf("Exploit %s ejecutado contra %s:%d", suggestion.ModuleName, suggestion.Target, suggestion.Port), nil
}
