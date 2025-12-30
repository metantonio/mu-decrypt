# Mu Online Packet Decryptor & Injector Engine

Este proyecto es una suite avanzada diseñada para la interceptación, análisis y manipulación del protocolo de comunicación de Mu Online. Cuenta con una arquitectura asíncrona robusta y una interfaz web moderna para un análisis cómodo en tiempo real.

## Características Principales

- 🚀 **Dashboard Web Moderno**: Interfaz fluida para monitorizar paquetes e inyectar datos con un clic.
- 🔍 **Escáner de Procesos**: Detección automática de procesos `main.exe` y sus conexiones activas.
- 🛠️ **Gestión de Redirección**: Soporte para edición segura del archivo `hosts` con restauración automática.
- 🧩 **Parser de OpCodes**: Identificación de acciones comunes como Movimiento, Teletransporte y Chat.
- 🔒 **Decodificación**: Soporte inicial para SimpleModulus (C3/C4).

## Requisitos

- Python 3.8+
- Node.js & npm (Para el Dashboard)
- Privilegios de Administrador (Opcional, para modificar el archivo `hosts`)

## Instalación

### 1. Backend (Python)
```powershell
# Crear y activar entorno virtual
python -m venv venv
.\venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

### 2. Frontend (React)
```powershell
cd dashboard
npm install
```

## Uso

### Lanzamiento Completo (Recomendado)

Inicia el servidor backend con la interfaz web y el escaneo automático:
```powershell
#python main.py --scan --ui
python main.py --scan --ui --redirect connect.muonline.com
#python main.py --scan --port 44405 --host 139.5.226.83 --remote-port 44405 --ui
#python main.py --scan --ui --transparent
#python main.py --scan --ui --memory
```


Luego, en otra terminal, lanza el Dashboard:
```powershell
cd dashboard
npm run dev
```
Accede a la interfaz en `http://localhost:5173`.

### Argumentos de la CLI:
- `--ui`: Activa el bridge para la interfaz web (WebSocket).
- `--scan`: Escanea procesos activos para autoconfigurar el proxy.
- `--redirect <dominio>`: Redirige un dominio (ej. `connect.muonline.com`) a `127.0.0.1` usando el archivo hosts.
- `--port <puerto>`: Puerto local para la escucha del proxy (default: 55901).

## Estructura del Proyecto

- `src/fast_server.py`: Bridge FastAPI para comunicación en tiempo real con la UI.
- `src/hosts_manager.py`: Utilidad para gestión segura de redirección local.
- `src/packet.py`: Lógica de análisis y identificación de opcodes.
- `src/proxy.py`: Servidor proxy asíncrono con inyección dinámica.
- `dashboard/`: Frontend React + Vite con diseño premium.

## Disclaimer
Este proyecto tiene **fines educativos y de investigación únicamente**. El uso de estas herramientas en servidores oficiales puede violar los términos de servicio. Por favor, asegúrate de tener permiso antes de realizar análisis en infraestructuras de terceros.
