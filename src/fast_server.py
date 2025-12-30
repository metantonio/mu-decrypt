from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import logging
from .scanner import scan_mu_processes
from .hosts_manager import HostsManager

logger = logging.getLogger(__name__)

app = FastAPI()

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

# Queues for communication with the Proxy
packet_queue = asyncio.Queue()
command_queue = asyncio.Queue()

@app.get("/api/scan")
async def get_scan():
    """
    Returns a list of Mu Online processes and their connection details.
    """
    return scan_mu_processes()

@app.post("/api/redirect")
async def apply_redirect(data: dict):
    """
    Applies redirection for a specific domain.
    """
    domain = data.get("domain")
    if not domain:
        return {"status": "error", "message": "Domain is required"}
    
    hosts = HostsManager(domain)
    # Note: We assume the server is already running with enough privileges 
    # since it was launched from main.py
    if hosts.apply_redirection():
        return {"status": "success", "message": f"Redirected {domain} to 127.0.0.1"}
    return {"status": "error", "message": "Failed to apply redirection (Check Admin privileges)"}

@app.get("/api/status")
async def get_status():
    """
    Returns the current configuration of the proxy.
    """
    return {
        "status": "online",
        "has_callback": True
    }
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle commands from the UI (injection, etc.)
            try:
                cmd_data = json.loads(data)
                await command_queue.put(cmd_data)
            except Exception as e:
                logger.error(f"Error parsing UI command: {e}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)

async def send_packet_to_ui(packet_info: dict):
    """
    Called by the proxy to stream packet data to the UI.
    """
    await manager.broadcast({
        "type": "packet",
        "data": packet_info
    })

async def get_command_for_proxy():
    """
    Called by the proxy to check for commands from the UI.
    """
    if not command_queue.empty():
        return await command_queue.get()
    return None

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
