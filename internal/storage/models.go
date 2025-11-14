package storage

import "time"

// MetasploitSession sesión de Metasploit
type MetasploitSession struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"`
	Target   string    `json:"target"`
	Username string    `json:"username"`
	Via      string    `json:"via"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen"`
}
