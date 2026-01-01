# Mu Online Packet Decryptor & Injector Engine

This project is an advanced suite designed for interception, analysis, and manipulation of the Mu Online communication protocol. It features a robust asynchronous architecture and a modern web interface for convenient real-time analysis.

## Main Features

- 🚀 **Modern Web Dashboard**: Fluid interface to monitor packets and inject data with a single click.
- 🔍 **Process Scanner**: Automatic detection of `main.exe` processes and their active connections.
- 🛠️ **Redirection Management**: Support for secure editing of the `hosts` file with automatic restoration.
- 🧩 **OpCode Parser**: Identification of common actions such as Movement, Teleport, and Chat.
- 🔒 **Decoding**: Initial support for SimpleModulus (C3/C4).

## Requirements

- Python 3.8+
- Node.js & npm (For the Dashboard)
- Administrator Privileges (Optional, for modifying the `hosts` file)

## Installation

### 1. Backend (Python)
```powershell
# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Frontend (React)
```powershell
cd dashboard
npm install
```

## Usage

### Full Launch (Recommended)

Start the backend server with the web interface and automatic scanning:
```powershell
python main.py --scan --ui --memory
#python main.py --scan --ui --redirect connect.muonline.com
#python main.py --scan --port 44405 --host 139.5.226.83 --remote-port 44405 --ui
#python main.py --scan --ui --transparent
```

Then, in another terminal, launch the Dashboard:
```powershell
cd dashboard
npm run dev
```
Access the interface at `http://localhost:5173`.

### CLI Arguments:
- `--ui`: Activates the bridge for the web interface (WebSocket).
- `--scan`: Scans active processes to auto-configure the proxy.
- `--redirect <domain>`: Redirects a domain (e.g. `connect.muonline.com`) to `127.0.0.1` using the hosts file.
- `--port <port>`: Local port for proxy listening (default: 55901).

## Project Structure

- `src/fast_server.py`: FastAPI bridge for real-time communication with the UI.
- `src/hosts_manager.py`: Utility for secure local redirection management.
- `src/packet.py`: Analysis logic and opcode identification.
- `src/proxy.py`: Asynchronous proxy server with dynamic injection.
- `dashboard/`: React + Vite frontend with premium design.

## Disclaimer
This project is for **educational and research purposes only**. Using these tools on official servers may violate terms of service. Please ensure you have permission before performing analysis on third-party infrastructures.
