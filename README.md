# Mu Online Packet Decryptor & Injector Concept

Este proyecto es una prueba de concepto (PoC) diseñada para el estudio de la seguridad en el protocolo de comunicación de Mu Online. Permite interceptar, decodificar e inyectar paquetes entre el cliente y el servidor.

## Requisitos

- Python 3.8 o superior
- Pip (gestor de paquetes de Python)

## Instalación

Sigue estos pasos para configurar el proyecto en un entorno virtual:

1. **Clonar o descargar el repositorio** en tu máquina local.
2. **Abrir una terminal** en la carpeta raíz del proyecto (`mu-decrypt`).
3. **Crear un entorno virtual**:
   ```powershell
   # En Windows
   python -m venv venv
   ```
4. **Activar el entorno virtual**:
   ```powershell
   # En Windows
   .\venv\Scripts\activate
   ```
5. **Instalar las dependencias**:
   ```powershell
   pip install -r requirements.txt
   ```

## Uso

Para iniciar el proxy interceptor:

```powershell
python main.py --port 55901 --host connect.muonline.com --remote-port 44405
```

### Argumentos:
- `--port`: Puerto local donde escuchará el proxy (ej. 55901).
- `--host`: Dirección del servidor real de Mu Online.
- `--remote-port`: Puerto del servidor real (ej. 44405 para ConnectServer).

## Estructura del Proyecto

- `src/decryption.py`: Lógica de decodificación SimpleModulus (C3/C4).
- `src/packet.py`: Parser de cabeceras de paquetes (C1-C4).
- `src/proxy.py`: Implementación del servidor proxy asíncrono.
- `main.py`: Punto de entrada de la aplicación.

## Disclaimer
Este proyecto tiene **fines educativos y de investigación únicamente**. El uso de estas herramientas en servidores oficiales puede violar los términos de servicio.
