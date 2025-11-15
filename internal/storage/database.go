package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Database gestión de BD
type Database struct {
	db *sql.DB
}

// Logger interface para logging
type Logger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// NewDatabase crea nueva BD
func NewDatabase(dbPath string, logger Logger) (*Database, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("error abriendo DB: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("error conectando DB: %w", err)
	}
	// Habilitar autocommit
	_, err = db.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("error configurando WAL: %w", err)
	}
	database := &Database{db: db}
	if err := database.createTables(); err != nil {
		return nil, err
	}

	logger.Infof("Base de datos inicializada: %s", dbPath)
 return database, nil
}

// createTables crea estructura de tablas
func (db *Database) createTables() error {


	// Ejecutar cada statement por separado
	statements := []string{
		`CREATE TABLE IF NOT EXISTS scan_results (
			id TEXT PRIMARY KEY,
			timestamp DATETIME,
			target TEXT,
			start_time DATETIME,
			end_time DATETIME,
			total_hosts INTEGER,
			status_code INTEGER,
			data TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS hosts (
			id TEXT PRIMARY KEY,
			scan_id TEXT,
			ip TEXT UNIQUE,
			hostname TEXT,
			status TEXT,
			os TEXT,
			data TEXT,
			FOREIGN KEY(scan_id) REFERENCES scan_results(id)
		)`,
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			id TEXT PRIMARY KEY,
			host_ip TEXT,
			port INTEGER,
			service TEXT,
			cve TEXT,
			cwe TEXT,
			owasp TEXT,
			severity TEXT,
			description TEXT,
			detected_at DATETIME
		)`,
	}

	for _, stmt := range statements {
		if _, err := db.db.Exec(stmt); err != nil {
			return fmt.Errorf("error ejecutando schema: %w", err)
		}
	}

	return nil
}


// Close cierra la BD
func (db *Database) Close() error {
	return db.db.Close()
}

// SaveScan guarda resultado de escaneo
func (db *Database) SaveScan(id, target string, data []byte) error {
	query := `INSERT INTO scan_results (id, timestamp, target, data) VALUES (?, datetime('now'), ?, ?)`
	
	result, err := db.db.Exec(query, id, target, string(data))
	if err != nil {
		return fmt.Errorf("error insertando scan: %w", err)
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error obteniendo rows affected: %w", err)
	}
	
	if rowsAffected == 0 {
		return fmt.Errorf("no rows inserted")
	}
	
	return nil
}


//GetScan recupera escaneo
func (db *Database) GetScan(id string) (string, error) {
	var data string
	err := db.db.QueryRow("SELECT data FROM scan_results WHERE id = ?", id).Scan(&data)
	return data, err
}


// SaveScanResult guarda resultado completo de escaneo con hosts y puertos
func (db *Database) SaveScanResult(scanID string, result interface{}) error {
	// Aquí implementaremos la lógica de guardado
	// Por ahora es un placeholder
	return nil
}

// GetAllScans recupera todos los escaneos
func (db *Database) GetAllScans() ([]map[string]interface{}, error) {
	rows, err := db.db.Query("SELECT id, timestamp, target, total_hosts, status_code FROM scan_results ORDER BY timestamp DESC LIMIT 50")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var id, timestamp, target string
		var totalHosts, statusCode int
		err := rows.Scan(&id, &timestamp, &target, &totalHosts, &statusCode)
		if err != nil {
			continue
		}
		scans = append(scans, map[string]interface{}{
			"id":          id,
			"timestamp":   timestamp,
			"target":      target,
			"total_hosts": totalHosts,
			"status_code": statusCode,
		})
	}

	return scans, nil
}

// DeleteScan elimina un escaneo
func (db *Database) DeleteScan(id string) error {
	_, err := db.db.Exec("DELETE FROM scan_results WHERE id = ?", id)
	return err
}


// ScanInfo representa info básica de un escaneo
type ScanInfo struct {
	ID        string
	Timestamp string
	Target    string
	TotalHosts int
}

// GetScanHistory obtiene historial de escaneos
func (db *Database) GetScanHistory(limit int) ([]ScanInfo, error) {
	query := `SELECT id, timestamp, target, total_hosts FROM scan_results ORDER BY timestamp DESC LIMIT ?`
	rows, err := db.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []ScanInfo
	for rows.Next() {
		var scan ScanInfo
		err := rows.Scan(&scan.ID, &scan.Timestamp, &scan.Target, &scan.TotalHosts)
		if err != nil {
			continue
		}
		scans = append(scans, scan)
	}

	return scans, nil
}

// GetScanData obtiene datos completos de un escaneo
func (db *Database) GetScanData(id string) (string, error) {
	var data string
	err := db.db.QueryRow("SELECT data FROM scan_results WHERE id = ?", id).Scan(&data)
	return data, err
}

// SaveScanComplete guarda escaneo con todos los detalles
func (db *Database) SaveScanComplete(id, target string, startTime, endTime time.Time, totalHosts, statusCode int, data []byte) error {
	query := `INSERT INTO scan_results (id, timestamp, target, start_time, end_time, total_hosts, status_code, data) 
			VALUES (?, datetime('now'), ?, ?, ?, ?, ?, ?)`
	
	result, err := db.db.Exec(query, id, target, startTime, endTime, totalHosts, statusCode, string(data))
	if err != nil {
		return fmt.Errorf("error insertando scan: %w", err)
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error obteniendo rows affected: %w", err)
	}
	
	if rowsAffected == 0 {
		return fmt.Errorf("no rows inserted")
	}
	
	return nil
}
