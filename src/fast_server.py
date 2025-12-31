from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import logging
from .scanner import scan_mu_processes
from .hosts_manager import HostsManager
from .memory import MemoryManager

logger = logging.getLogger(__name__)

app = FastAPI()

@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"[*] API Request: {request.method} {request.url.path}")
    return await call_next(request)

# Track active redirection for UI diagnostics
active_redirection = {"domain": None, "status": "none", "mode": "hosts"}
transparent_mode_active = False # Set by main.py if --transparent is used
memory_instance = None # Injected by main.py
memory_stats = {
    "hp": 0, "max_hp": 0, "mp": 0, "max_mp": 0, "level": 0,
    "hp_offset": 0, "max_hp_offset": 0, "mp_offset": 0, "max_mp_offset": 0, "level_offset": 0,
    "connected": False, "base_address": 0
}
memory_offsets = {"hp": 0, "max_hp": 0, "mp": 0, "max_mp": 0, "level": 0}

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
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

@app.post("/api/config")
async def set_config(data: dict):
    """Sets global configuration flags from main.py"""
    global transparent_mode_active
    transparent_mode_active = data.get("transparent", False)
    if transparent_mode_active:
        active_redirection["mode"] = "divert"
        active_redirection["status"] = "success" # Divert is handled at network level
    return {"status": "ok"}

@app.post("/api/redirect")
async def apply_redirect(data: dict):
    """
    Applies redirection for a specific domain.
    """
    domain = data.get("domain")
    if not domain:
        return {"status": "error", "message": "Domain is required"}

    if transparent_mode_active:
        active_redirection["domain"] = domain
        active_redirection["status"] = "success"
        active_redirection["mode"] = "divert"
        return {"status": "success", "message": f"Modo Transparente (WinDivert) activo para {domain}. Ignorando archivos hosts."}

    hosts = HostsManager(domain)
    # Note: We assume the server is already running with enough privileges 
    # since it was launched from main.py
    active_redirection["domain"] = domain
    active_redirection["mode"] = "hosts"
    if hosts.apply_redirection():
        # Verify if it actually worked (anti-cheat check)
        if hosts.verify_resolution():
            active_redirection["status"] = "success"
            return {"status": "success", "message": f"Redirección aplicada: {domain} -> 127.0.0.1 (DNS verificado)"}
        else:
            active_redirection["status"] = "warning"
            return {"status": "warning", "message": f"Archivo hosts actualizado, pero {domain} NO resuelve a 127.0.0.1. El Anti-Cheat podría estar bloqueando."}
    
    active_redirection["status"] = "error"
    return {"status": "error", "message": "Failed to apply redirection (Check Admin privileges)"}

@app.post("/api/verify")
async def verify_dns(data: dict):
    """
    Verifies if a domain resolves to 127.0.0.1.
    """
    domain = data.get("domain")
    if not domain:
        return {"status": "error", "message": "Domain is required"}
    
    hosts = HostsManager(domain)
    if hosts.verify_resolution():
        return {"status": "success", "message": f"{domain} está redirigido correctamente."}
    return {"status": "warning", "message": f"{domain} NO está apuntando a 127.0.0.1. El juego podría estar ignorando el archivo hosts."}
@app.get("/api/status")
async def get_status():
    """
    Returns the current configuration of the proxy.
    """
    return {
        "status": "online",
        "redirection": active_redirection
    }
@app.websocket("/ws")
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

@app.get("/api/memory")
async def get_memory_stats():
    return {**memory_stats, "offsets": memory_offsets}

@app.post("/api/memory/attach")
async def attach_memory(data: dict):
    global memory_instance
    pid = data.get("pid")
    name = data.get("name", "main.exe")
    
    if not pid:
        return {"status": "error", "message": "PID is required"}
        
    try:
        # Check if already connected to this PID
        if memory_instance and memory_instance.pid == pid and memory_instance.running:
            return {"status": "success", "message": "Already connected to this process"}

        # Stop old instance if exists
        if memory_instance:
            memory_instance.stop()

        mem = MemoryManager(name, pid=pid)
        if mem.connect():
            memory_instance = mem
            loop = asyncio.get_event_loop()
            mem.start_polling(callback=lambda s: asyncio.run_coroutine_threadsafe(send_memory_to_ui(s), loop))
            print(f"[*] API: Memoria conectada exitosamente a {name} (PID: {pid})")
            return {"status": "success", "message": f"Attached to {name} ({pid})"}
        else:
            return {"status": "error", "message": "Failed to connect to process. Are you admin?"}
    except Exception as e:
        logger.error(f"Error attaching memory: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/api/memory/offsets")
async def update_offsets(data: dict):
    global memory_offsets, memory_instance
    memory_offsets.update(data)
    if memory_instance:
        print(f"[*] API: Actualizando offsets en motor de memoria: {data}")
        memory_instance.update_offsets(data)
    return {"status": "success", "offsets": memory_offsets}

@app.post("/api/memory/search")
async def search_memory(data: dict):
    global memory_instance
    if not memory_instance:
        return {"status": "error", "message": "Memory engine not running"}
    value = data.get("value")
    type_name = data.get("type", "int")
    if value is None: return {"status": "error", "message": "Value is required"}
    
    val_typed = float(value) if type_name == "float" else int(value)
    results = await asyncio.to_thread(memory_instance.search_value, val_typed, type_name)
    return {"status": "success", "count": len(results), "results": [hex(r) for r in results[:100]]}

@app.post("/api/memory/filter")
async def filter_memory(data: dict):
    global memory_instance
    if not memory_instance:
        return {"status": "error", "message": "Memory engine not running"}
    value = data.get("value")
    type_name = data.get("type", "int")
    if value is None: return {"status": "error", "message": "Value is required"}
    
    val_typed = float(value) if type_name == "float" else int(value)
    results = await asyncio.to_thread(memory_instance.filter_candidates, val_typed, type_name)
    return {"status": "success", "count": len(results), "results": [hex(r) for r in results[:100]]}

@app.post("/api/memory/calibrate")
async def calibrate_memory(data: dict):
    global memory_instance
    if not memory_instance:
        return {"status": "error", "message": "Memory engine not running"}
    
    anchor_hex = data.get("anchor")
    values = data.get("values", {}) # {"hp": 500.0, "mp": 200.0}
    
    if not anchor_hex:
        return {"status": "error", "message": "Anchor address is required"}
    
    try:
        anchor_addr = int(anchor_hex, 16)
        discovered = await asyncio.to_thread(memory_instance.discover_nearby_stats, anchor_addr, values)
        return {"status": "success", "offsets": {k: hex(v) for k, v in discovered.items()}}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/memory/write")
async def write_memory(data: dict):
    global memory_instance
    if not memory_instance:
        return {"status": "error", "message": "Memory engine not running"}
    
    address_hex = data.get("address")
    value = data.get("value")
    type_name = data.get("type", "int")
    
    if not address_hex or value is None:
        return {"status": "error", "message": "Address and value are required"}
        
    try:
        address = int(address_hex, 16)
        success = await asyncio.to_thread(memory_instance.write_value, address, value, type_name)
        if success:
            return {"status": "success", "message": f"Value {value} written to {address_hex}"}
        else:
            return {"status": "error", "message": "Failed to write memory. Try as admin?"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

async def send_memory_to_ui(stats: dict):
    """Streams memory stats to the UI via WebSocket"""
    global memory_stats, memory_instance
    # print(f"[*] WS BROADCAST MEMORY: Enviando stats a {len(manager.active_connections)} clientes UI.")
    memory_stats.update(stats)
    memory_stats["connected"] = True
    if memory_instance:
        memory_stats["base_address"] = memory_instance.base_address
    
    await manager.broadcast({
        "type": "memory",
        "data": memory_stats
    })

async def send_packet_to_ui(packet_info: dict):
    """
    Called by the proxy to stream packet data to the UI.
    """
    if manager.active_connections:
        print(f"[*] WS BROADCAST: Enviando paquete a {len(manager.active_connections)} clientes UI.")
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
