package export

import (
	"encoding/json"
	"os"

	"github.com/juanotejeda/REStrike/pkg/models"
)

// ExportToJSON exporta resultado a JSON
func ExportToJSON(filename string, result *models.ScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
