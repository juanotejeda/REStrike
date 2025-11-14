# REStrike - Herramienta de Pentesting Visual

![Version](https://img.shields.io/badge/version-0.1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Language](https://img.shields.io/badge/language-Go-00ADD8)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

Herramienta multiplataforma de pentesting visual, escaneo de red y explotación, con visualización de grafos, integración con Nmap, Metasploit y enfoque OWASP/CWE. Destinada a laboratorio y capacitación.

**Proyecto Open Source de la comunidad Remote Execution (#RE)**

---

## ✨ Características Principales

- 🔍 **Escaneo de Red Inteligente**: Integración completa con Nmap + scripts NSE automáticos
- 📊 **Visualización Gráfica Interactiva**: Grafo en tiempo real de hosts, servicios y relaciones
- 🎯 **Explotación Integrada**: Cliente RPC para Metasploit Framework con soporte de payloads
- 📋 **Reportes Profesionales**: Generación automática en PDF, HTML y JSON
- 🏷️ **Categorización Inteligente**: Clasificación automática OWASP Top 10 y CWE
- 💾 **Base de Datos Local**: SQLite con cifrado AES-256 de credenciales
- 🖥️ **Multiplataforma Nativa**: Compilación para Linux, macOS, Windows
- 🎨 **GUI Moderna**: Interfaz gráfica con Fyne (sin dependencias externas)
- 🔐 **Seguridad Integrada**: Logging auditado, control RBAC, validación de entrada
- 👥 **Multi-usuario**: Sistema de roles (Admin, Pentester, Viewer)
- 📈 **Dashboard en Tiempo Real**: Estadísticas dinámicas y progreso de escaneos
- 🎓 **Educativo**: Perfecto para laboratorios, capacitación y CTF

---

## 🚀 Instalación Rápida

### Requisitos Mínimos

- Go 1.21 o superior
- Nmap instalado en el sistema
- Git

### Instalación en Linux Debian/Ubuntu

sudo apt-get update
sudo apt-get install -y nmap golang-go git libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev libgl1-mesa-dev

git clone https://github.com/juanotejeda/REStrike.git
cd REStrike
go mod download && go mod tidy
make build
./restrike

### Instalación en Linux Arch/Manjaro

sudo pacman -S nmap go git libx11 libxcursor libxrandr libxinerama libxi mesa

git clone https://github.com/juanotejeda/REStrike.git
cd REStrike
go mod download && go mod tidy
make build
./restrike

### Instalación en macOS

brew install nmap go git

git clone https://github.com/juanotejeda/REStrike.git
cd REStrike
go mod download && go mod tidy
make build
./restrike

### Instalación en Windows

1. Descargar Go desde https://golang.org/dl/ (instalar)
2. Descargar Nmap desde https://nmap.org/download.html (instalar)
3. Descargar Git desde https://git-scm.com/ (instalar)
4. En PowerShell:

git clone https://github.com/juanotejeda/REStrike.git
cd REStrike
go mod download
go mod tidy
go build -o restrike.exe .\cmd\restrike
.\restrike.exe

---

## 📖 Uso Rápido

### Modo GUI (Recomendado)

./restrike

Pasos:
1. Iniciar aplicación
2. Click en "Nuevo Escaneo"
3. Ingresar target (ejemplo: 192.168.1.0/24)
4. Seleccionar opciones
5. Click en "Escanear"
6. Ver resultados en Dashboard
7. Generar reporte (PDF/HTML)

### Modo Headless (Línea de comandos)

# Escaneo simple
./restrike -headless -target 192.168.1.1

# Escaneo detallado
./restrike -headless -target 192.168.1.0/24 -v

# Con configuración personalizada
./restrike -headless -target 192.168.1.1 -config custom.yaml

### Flags Disponibles

-v              Verbose (salida detallada)
-headless       Modo sin GUI
-target string  Target a escanear (CIDR, IP, rango)
-config string  Ruta config.yaml (default: config.yaml)
-h, -help       Mostrar ayuda

---

## 🏗️ Estructura del Proyecto

REStrike/
├── cmd/
│   └── restrike/
│       └── main.go
├── internal/
│   ├── scanner/
│   │   ├── nmap.go
│   │   └── vuln_detector.go
│   ├── exploit/
│   │   └── metasploit.go
│   ├── gui/
│   │   └── app.go
│   ├── report/
│   │   └── generator.go
│   └── storage/
│       └── database.go
├── pkg/
│   └── models/
│       └── types.go
├── configs/
│   └── config.yaml
├── Makefile
├── go.mod
├── go.sum
├── LICENSE
├── .gitignore
└── README.md
---

## ⚙️ Configuración

Crear archivo config.yaml en la raíz del proyecto:

database:
  path: ~/.restrike/restrike.db
  memory: false
  backup: true

nmap:
  path: /usr/bin/nmap
  timeout: 3600
  ports: "1-10000"
  nse_scripts:
    - vuln
    - exploit
    - http-enum
    - ssl-*
    - smb-vuln-*
  aggressive_mode: false
  os_detection: true
  service_version: true
  max_parallelism: 64

metasploit:
  enabled: false
  host: localhost
  port: 55553
  username: msf
  password: change_me
  ssl: false
  auto_connect: false

security:
  enable_logging: true
  log_path: ~/.restrike/logs/restrike.log
  log_level: info
  encrypt_credentials: true
  master_key_env: RESTRIKE_KEY
  session_timeout: 3600
  max_login_attempts: 5

gui:
  theme: dark
  language: es
  width: 1400
  height: 900
  auto_connect: false
  show_tips: true

reports:
  output_dir: ./reports
  auto_open: false
  include_recommendations: true
  include_raw_data: false

---

## 🔍 Módulos Principales

### Scanner (Nmap)

- Escaneo de hosts y puertos
- Detección de servicios y versiones
- Detección de Sistema Operativo
- Ejecución de scripts NSE personalizados
- Parsing de resultados XML

### Exploit (Metasploit)

- Cliente RPC para Metasploit Framework
- Listado dinámico de módulos
- Ejecución de exploits
- Gestión de payloads
- Control de sesiones

### GUI (Fyne)

- Dashboard con estadísticas
- Tabs para escaneo, vulnerabilidades, exploits, reportes
- Visualización interactiva de grafos
- Formularios para configuración
- Logs en tiempo real

### Report (PDF/HTML)

- Generación automática de reportes
- Templates customizables
- Información de hosts y vulnerabilidades
- Recomendaciones automáticas
- Exportación en múltiples formatos

### Storage (SQLite)

- Persistencia de resultados
- Cifrado de credenciales
- Historial de escaneos
- Base de datos local sin conexión a internet

---

## 🏷️ Categorización OWASP/CWE

REStrike detecta y clasifica automáticamente vulnerabilidades según OWASP Top 10 2021 y CWE.

### OWASP Top 10 2021

- A01:2021 - Broken Access Control (CWE-284)
- A02:2021 - Cryptographic Failures (CWE-319, CWE-327)
- A03:2021 - Injection (CWE-89, CWE-79)
- A04:2021 - Insecure Design (CWE-434)
- A05:2021 - Security Misconfiguration (CWE-16)
- A06:2021 - Vulnerable and Outdated Components (CWE-1035)
- A07:2021 - Identification and Authentication Failures (CWE-307)
- A08:2021 - Software and Data Integrity Failures (CWE-345)
- A09:2021 - Logging and Monitoring Failures (CWE-778)
- A10:2021 - Server-Side Request Forgery (CWE-918)

### Ejemplos de Detección

- Telnet activo: A02:2021 (Cryptographic Failures)
- FTP sin cifrado: A02:2021
- HTTP sin HTTPS: A02:2021
- Bases de datos expuestas: A01:2021
- SSH desactualizado: A06:2021
- SMB vulnerable: A06:2021

---

## 🔐 Seguridad

### Características Implementadas

✅ Cifrado AES-256-GCM para credenciales en BD
✅ Hashing bcrypt para contraseñas de usuario
✅ Logging auditado de todas las acciones
✅ Control RBAC con 3 niveles de acceso
✅ Validación de entrada en todos los formularios
✅ HTTPS/TLS para conexiones Metasploit
✅ Permisos de archivo restringidos (0600)
✅ Session management seguro
✅ Rate limiting en intentos de login

### ⚠️ Notas de Seguridad

⚠️ Solo usar en ambientes autorizados
⚠️ Responsabilidad del usuario sobre el uso ético
⚠️ No almacenar credenciales reales en config.yaml
⚠️ Usar variable de entorno para master key en producción
⚠️ Revisar logs regularmente

---

## 🧪 Testing

# Todos los tests
make test

# Con cobertura
go test -cover ./...

# Módulo específico
go test -v ./internal/scanner
go test -v ./internal/exploit
go test -v ./internal/report

# Lint
make lint

# Formato
make fmt

---

## 📦 Compilación

# Build por defecto
make build

# Build para Linux
GOOS=linux GOARCH=amd64 go build -o restrike ./cmd/restrike

# Build para macOS
GOOS=darwin GOARCH=amd64 go build -o restrike ./cmd/restrike

# Build para Windows
GOOS=windows GOARCH=amd64 go build -o restrike.exe ./cmd/restrike

# Build con versión
go build -ldflags "-X main.version=0.1.0" -o restrike ./cmd/restrike

# Instalar globalmente
make install

---

## 🤝 Contribuir

### Pasos para Contribuir

1. Fork el repositorio
   git clone https://github.com/TU_USUARIO/REStrike.git
   cd REStrike

2. Crear rama de feature
   git checkout -b feature/mi-feature

3. Hacer cambios
   # Editar archivos
   # Agregar tests si es necesario

4. Commit y push
   git add .
   git commit -m "Descripción clara del cambio"
   git push origin feature/mi-feature

5. Crear Pull Request
   - En GitHub: Click "New Pull Request"
   - Escribir descripción detallada
   - Esperar review

### Estándares de Código

- Usar gofmt para formatear código
- Comentar funciones públicas
- Tests unitarios para nuevas funcionalidades
- Seguir principios SOLID y Clean Code
- Sin hardcode de credenciales
- Validar entrada de datos

---

## 🗺️ Roadmap

### Versión 0.2.0 (Próxima)

- Visualización avanzada de grafo con clustering
- Integración con API de vulnerabilidades (NVD, VulnDB)
- Editor visual de exploits
- Soporte para payloads personalizados
- Integración con Burp Suite

### Versión 0.3.0

- Autenticación multi-usuario
- Dashboard compartido en tiempo real
- Scheduler de escaneos automatizados
- Integración con Shodan API
- Soporte para wireless scanning (aircrack-ng)

### Versión 0.5.0 (Largo plazo)

- API REST completa
- Aplicación móvil (iOS/Android)
- Integración con SIEM
- Machine Learning para detección de anomalías
- Nube/Cluster support

---

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver archivo LICENSE para más detalles.

MIT License

Copyright (c) 2024 REStrike Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 👥 Autores y Contribuidores

- Juan O. Tejeda - Creador Principal
- Comunidad #RE - Feedback y Testing

---

## 📞 Soporte y Contacto

- Issues: https://github.com/juanotejeda/REStrike/issues
- Discussions: https://github.com/juanotejeda/REStrike/discussions
- Email: juanotejeda@gmail.com

---

## 🙏 Agradecimientos

Especial agradecimiento a:
- Daniel Godoy
- #RemoteExecution
- Nmap Team - Por la excelente herramienta de escaneo
- Metasploit Framework - Por el framework
