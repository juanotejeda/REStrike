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
- 📊 **Visualización Gráfica Interactiva**: Grafo en tiempo real de hosts, servicios y relaciones - Proximamente :D
- 🎯 **Explotación Integrada (condicional)**: Actualmente solo se listan exploits a partir de metadatos JSON locales
- 📋 **Reportes Profesionales**: Generación automática en PDF, HTML y JSON
- 🏷️ **Categorización Inteligente**: Clasificación automática OWASP Top 10 y CWE
- 💾 **Base de Datos Local**: SQLite con cifrado AES-256 de credenciales
- 🖥️ **Multiplataforma Nativa**: Compilación para Linux, macOS, Windows
- 🎨 **GUI Moderna**: Interfaz gráfica con Fyne (sin dependencias externas)
- 🔐 **Seguridad Integrada**: Logging auditado, control RBAC, validación de entrada - Proximamente :D
- 👥 **Multi-usuario**: Sistema de roles (Admin, Pentester, Viewer) - Proximamente :D
- 📈 **Dashboard en Tiempo Real**: Estadísticas dinámicas y progreso de escaneos
- 🎓 **Educativo**: Perfecto para laboratorios, capacitación y CTF

---

## 🚀 Instalación Rápida

### Requisitos Mínimos

- Go 1.21 o superior.
- Nmap instalado en el sistema.
- Metasploit instalado en el sistema.
- Git.

### Instalación en Linux Debian/Ubuntu / Kali

#### Actualizamos el repositorio e instalamos las librerias necesarias.
```bash
sudo apt-get update
sudo apt-get install -y nmap golang-go git libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev libgl1-mesa-dev
```
#### Clonamos el git, ingresamos a la carpeta de la aplicacion y desdecargamos los modulos necesarios para compilar la aplicacion.
```bash
git clone https://github.com/juanotejeda/REStrike.git
cd REStrike
go mod download && go mod tidy
make build
./restrike
```


---

## 📖 Uso Rápido

### Modo GUI (Recomendado)
```bash

./restrike

```


Pasos:

1. Iniciar aplicación
2. Click en "Nuevo Escaneo"
3. Ingresar target (ejemplo: 192.168.1.0/24)
4. Seleccionar opciones
5. Click en "Escanear"
6. Ver resultados en Dashboard
7. Generar reporte (PDF/HTML)

### Modo Headless (Línea de comandos)
```bash
./restrike -headless -target 192.168.1.1

```

---

## 🔍 Módulos Principales

### Scanner (Nmap)

- Escaneo de hosts y puertos
- Detección de servicios y versiones
- Detección de Sistema Operativo
- Ejecución de scripts NSE personalizados
- Parsing de resultados XML

### Exploit (Metasploit)

- Los exploits se cargan y listan desde el archivo de metadatos JSON local generado por Metasploit  
- Actualmente, REStrike **no ejecuta exploits vía cliente RPC de Metasploit**  
- Ejecución de exploits mediante cliente RPC o msfconsole está planificada para próximas versiones

### GUI (Fyne)

- Dashboard con estadísticas
- Tabs para escaneo, vulnerabilidades, exploits y reportes
- Visualización interactiva de grafos
- Formularios para configuración
- Logs en tiempo real

---

## 🗺️ Roadmap

### Versión 0.2.0 (Próxima)

- Integración para ejecutar exploits vía cliente RPC o msfconsole
- Gestión avanzada de sesiones de Metasploit
- Mejoras en sincronización con Metasploit Framework

---

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver archivo LICENSE para más detalles.

---

## 🤝 Contribuir

Por favor sigue el flujo clásico de git: fork, rama de feature, commit claramente documentados, pull request con descripción.

---

## 📞 Soporte

- Issues: https://github.com/juanotejeda/REStrike/issues  
- Discussions: https://github.com/juanotejeda/REStrike/discussions  
- Email: juanotejeda@gmail.com

---

