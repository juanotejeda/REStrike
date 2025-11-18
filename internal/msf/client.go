package msf

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/vmihailenco/msgpack/v5"
)

// Client cliente para Metasploit RPC
type Client struct {
	Host     string
	Port     int
	Password string
	Token    string
	client   *http.Client
}

// NewClient crea un nuevo cliente Metasploit
func NewClient(host string, port int, password string) *Client {
	return &Client{
		Host:     host,
		Port:     port,
		Password: password,
		client:   &http.Client{},
	}
}

// call realiza una llamada RPC
func (c *Client) call(method string, args ...interface{}) (map[string]interface{}, error) {
	url := fmt.Sprintf("http://%s:%d/api/", c.Host, c.Port)

	// Construir payload
	payload := []interface{}{method}
	if c.Token != "" {
		payload = append(payload, c.Token)
	}
	payload = append(payload, args...)

	// Serializar con MessagePack
	data, err := msgpack.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error serializando: %w", err)
	}

	// Hacer request
	resp, err := c.client.Post(url, "binary/message-pack", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("error en request: %w", err)
	}
	defer resp.Body.Close()

	// Decodificar respuesta
	var result map[string]interface{}
	decoder := msgpack.NewDecoder(resp.Body)
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("error decodificando: %w", err)
	}

	// Verificar errores
	if errMsg, ok := result["error"]; ok {
		return nil, fmt.Errorf("error MSF: %v", errMsg)
	}

	return result, nil
}

// Login autentica con Metasploit
func (c *Client) Login() error {
	result, err := c.call("auth.login", "msf", c.Password)
	if err != nil {
		return err
	}

	// El token puede venir como string o []byte
	if token, ok := result["token"].(string); ok {
		c.Token = token
		return nil
	}
	
	if tokenBytes, ok := result["token"].([]byte); ok {
		c.Token = string(tokenBytes)
		return nil
	}

	return fmt.Errorf("no se obtuvo token, respuesta: %v", result)
}

// SearchModules busca módulos por palabra clave
func (c *Client) SearchModules(query string) ([]string, error) {
	result, err := c.call("module.search", query)
	if err != nil {
		return nil, err
	}

	if modules, ok := result["modules"].([]interface{}); ok {
		var moduleNames []string
		for _, m := range modules {
			if name, ok := m.(string); ok {
				moduleNames = append(moduleNames, name)
			}
		}
		return moduleNames, nil
	}

	return []string{}, nil
}

// GetModuleInfo obtiene información de un módulo
func (c *Client) GetModuleInfo(moduleType, moduleName string) (map[string]interface{}, error) {
	return c.call("module.info", moduleType, moduleName)
}

// ExecuteModule ejecuta un módulo exploit
func (c *Client) ExecuteModule(moduleType, moduleName string, options map[string]string) (map[string]interface{}, error) {
	return c.call("module.execute", moduleType, moduleName, options)
}

// ListExploits lista todos los módulos exploit disponibles
func (c *Client) ListExploits() ([]string, error) {
	result, err := c.call("module.exploits")
	if err != nil {
		return nil, err
	}

	if modules, ok := result["modules"].([]interface{}); ok {
		var moduleNames []string
		for _, m := range modules {
			if name, ok := m.(string); ok {
				moduleNames = append(moduleNames, name)
			}
		}
		return moduleNames, nil
	}

	return []string{}, nil
}

// GetExploits busca exploits por servicio/puerto
func (c *Client) GetExploits(service string, port int) ([]map[string]interface{}, error) {
	// Listar todos los exploits
	allModules, err := c.ListExploits()
	if err != nil {
		return nil, err
	}

	var exploits []map[string]interface{}
	serviceLower := strings.ToLower(service)
	
	// Filtrar manualmente por servicio
	for _, name := range allModules {
		if len(exploits) >= 10 { // Limitar a 10 resultados
			break
		}
		
		nameLower := strings.ToLower(name)
		// Buscar coincidencia con el servicio
		if strings.Contains(nameLower, serviceLower) || 
		   strings.Contains(nameLower, fmt.Sprintf("%d", port)) {
			info, err := c.GetModuleInfo("exploit", name)
			if err != nil {
				continue
			}
			exploits = append(exploits, map[string]interface{}{
				"name": name,
				"info": info,
			})
		}
	}

	return exploits, nil
}
