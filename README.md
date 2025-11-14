# REStrike

**Herramienta multiplataforma para pentesting visual y automatizado, desarrollada en Go.**

Proyecto Open Source de la comunidad Remote Execution (#RE).

## Descripción
REStrike es una aplicación visual y multiplataforma pensada para laboratorios de pentesting y capacitación.

- Escaneo de red y servicios mediante Nmap + NSE Scripts
- Visualización gráfica de hosts, servicios y relaciones (tipo grafo)
- Integración con Metasploit Framework (RPC/API)
- Detalle y ataque orientado a vulnerabilidades OWASP Top 25 y CWE comunes
- Generación automática de informes
- Cifrado y manejo seguro de credenciales
- Modular, auditable y usable completamente en local

## Estructura inicial del proyecto
```
pentool/
├── cmd/
│   └── restrike/
│       └── main.go              # Punto de entrada
├── internal/
│   ├── scanner/                # Nmap y parsing
│   ├── exploit/                # Metasploit RPC
│   ├── graph/                  # Visualización y grafo
│   ├── report/                 # Generador de informes
│   ├── storage/                # DB local y cifrado
│   └── gui/                    # Interfaz y vistas
├── pkg/
│   └── models/                 # Modelos compartidos
└── go.mod
```

## Instalación rápida
```bash
# Clona el repositorio
git clone https://github.com/juanotejeda/REStrike.git
cd REStrike

# Inicializa Go Modules
go mod tidy
```

## Roadmap inicial
- [ ] Estructura base y escaneo
- [ ] GUI (Fyne) y visualización
- [ ] Integración Metasploit
- [ ] Sistema de reportes
- [ ] Seguridad y manejo de usuarios

## Créditos y comunidad
Remote Execution (#RE) | https://remoteexecution.org
