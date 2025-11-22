package msf

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/juanotejeda/REStrike/pkg/models"
)

// Client cliente para Metasploit que lee desde archivos JSON
type Client struct {
	MetadataPath string
	ExploitCache map[string]interface{}
}

// ModuleMetadata estructura de metadatos de Metasploit
type ModuleMetadata struct {
	Modules map[string]interface{} `json:"modules"`
}

// NewClient crea un nuevo cliente Metasploit
func NewClient(host string, port int, password string) *Client {
	// Por ahora ignoramos host/port/password y usamos archivos locales
	msfPath := filepath.Join(os.Getenv("HOME"), ".msf4", "store", "modules_metadata.json")
	
	return &Client{
		MetadataPath: msfPath,
		ExploitCache: make(map[string]interface{}),
	}
}

// Login simula autenticación (ya no necesaria con archivos)
func (c *Client) Login() error {
	fmt.Println("[*] Leyendo metadatos de Metasploit desde", c.MetadataPath)
	
	// Verificar que el archivo existe
	if _, err := os.Stat(c.MetadataPath); err != nil {
		return fmt.Errorf("archivo de metadatos no encontrado: %s", c.MetadataPath)
	}
	
	return nil
}

// ListExploits lista todos los módulos exploit disponibles
func (c *Client) ListExploits() ([]string, error) {
	// Leer archivo de metadatos
	data, err := ioutil.ReadFile(c.MetadataPath)
	if err != nil {
		return nil, fmt.Errorf("error leyendo metadatos: %w", err)
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("error parseando JSON: %w", err)
	}

	var exploits []string

	// Extraer exploits del JSON
	if modules, ok := metadata["modules"].(map[string]interface{}); ok {
		for path := range modules {
			// Filtrar solo exploits (contienen "exploits" en la ruta)
			if strings.Contains(path, "/exploits/") {
				exploits = append(exploits, path)
			}
		}
	}

	return exploits, nil
}

// GetExploits busca exploits por servicio/puerto
func (c *Client) GetExploits(service string, port int) ([]map[string]interface{}, error) {
	// Listar todos los exploits
	allModules, err := c.ListExploits()
	if err != nil {
		return nil, err
	}

	// Leer archivo para obtener metadatos completos
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
	modules := metadata["modules"].(map[string]interface{})

	// Filtrar y buscar coincidencias
	for _, modulePath := range allModules {
		if len(exploits) >= 10 { // Limitar a 10 resultados
			break
		}

		pathLower := strings.ToLower(modulePath)
		
		// Buscar coincidencia con el servicio
		if strings.Contains(pathLower, serviceLower) {
			moduleInfo, ok := modules[modulePath].(map[string]interface{})
			if !ok {
				continue
			}

			exploits = append(exploits, map[string]interface{}{
				"name": modulePath,
				"info": moduleInfo,
			})
		}
	}

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

	modules := metadata["modules"].(map[string]interface{})
	
	if moduleInfo, ok := modules[moduleName].(map[string]interface{}); ok {
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

// ExploitSuggestion sugerencia de exploit
type ExploitSuggestion struct {
	ModuleName  string
	Description string
	Rank        string
	Target      string
	Port        int
	Service     string
}

// SuggestExploits sugiere exploits basados en resultados de escaneo
func SuggestExploits(client *Client, result *models.ScanResult) ([]ExploitSuggestion, error) {
	var suggestions []ExploitSuggestion
	searched := make(map[string]bool)

	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			if port.State != "open" {
				continue
			}

			// Buscar por múltiples términos
			searchTerms := []string{
				port.Service,
				fmt.Sprintf("%s %d", port.Service, port.ID),
			}

			// Agregar versión si existe
			if port.Version != "" {
				searchTerms = append(searchTerms, fmt.Sprintf("%s %s", port.Service, port.Version))
			}

			for _, term := range searchTerms {
				if term == "" || searched[term] {
					continue
				}
				searched[term] = true

				// Buscar exploits para este servicio
				exploits, err := client.GetExploits(term, port.ID)
				if err != nil {
					continue
				}

				for _, exploit := range exploits {
					name, ok := exploit["name"].(string)
					if !ok {
						continue
					}

					description := "N/A"
					rank := "unknown"

					if info, ok := exploit["info"].(map[string]interface{}); ok {
						if desc, ok := info["description"].(string); ok {
							description = desc
						} else if descBytes, ok := info["description"].([]byte); ok {
							description = string(descBytes)
						}

						if r, ok := info["rank"].(string); ok {
							rank = r
						} else if rBytes, ok := info["rank"].([]byte); ok {
							rank = string(rBytes)
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
				}
			}
		}
	}

	return suggestions, nil
}

// ExecuteExploit ejecuta un exploit contra un target (simulado)
func ExecuteExploit(client *Client, suggestion ExploitSuggestion, lhost string, lport int) (string, error) {
	return fmt.Sprintf("Exploit %s ejecutado contra %s:%d", suggestion.ModuleName, suggestion.Target, suggestion.Port), nil
}
