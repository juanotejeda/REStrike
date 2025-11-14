package storage

import (
	"database/sql"
	"fmt"

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

	database := &Database{db: db}
	if err := database.createTables(); err != nil {
		return nil, err
	}

	logger.Infof("Base de datos inicializada: %s", dbPath)
	return database, nil
}

// createTables crea estructura de tablas
func (db *Database) createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scan_results (
		id TEXT PRIMARY KEY,
		timestamp DATETIME,
		target TEXT,
		start_time DATETIME,
		end_time DATETIME,
		total_hosts INTEGER,
		status_code INTEGER,
		data TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS hosts (
		id TEXT PRIMARY KEY,
		scan_id TEXT,
		ip TEXT UNIQUE,
		hostname TEXT,
		status TEXT,
		os TEXT,
		data TEXT,
		FOREIGN KEY(scan_id) REFERENCES scan_results(id)
	);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
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
	);
	`

	_, err := db.db.Exec(schema)
	return err
}

// Close cierra la BD
func (db *Database) Close() error {
	return db.db.Close()
}

// SaveScan guarda resultado de escaneo
func (db *Database) SaveScan(id, target string, data []byte) error {
	query := `INSERT INTO scan_results (id, timestamp, target, data) VALUES (?, datetime('now'), ?, ?)`
	_, err := db.db.Exec(query, id, target, string(data))
	return err
}

// GetScan recupera escaneo
func (db *Database) GetScan(id string) (string, error) {
	var data string
	err := db.db.QueryRow("SELECT data FROM scan_results WHERE id = ?", id).Scan(&data)
	return data, err
}
