import asyncio
import argparse
import sys
from src.proxy import MuProxy
from src.scanner import print_scan_report, get_target_from_scan
from src.hosts_manager import HostsManager
from src.divert import DivertManager
from src.memory import MemoryManager
from src.fast_server import app, send_packet_to_ui, get_command_for_proxy, send_memory_to_ui
import uvicorn

async def main():
    parser = argparse.ArgumentParser(description="Mu Online Packet Decryptor & Injector")
    parser.add_argument("--port", type=int, default=None, help="Local port to listen on (default: matches remote port if --scan is used, otherwise 55901)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Remote server host (default: 127.0.0.1)")
    parser.add_argument("--remote-port", type=int, default=44405, help="Remote server port (default: 44405)")
    parser.add_argument("--scan", action="store_true", help="Scan for Mu Online processes and ports")
    parser.add_argument("--redirect", type=str, help="Domain to redirect to localhost (requires admin)")
    parser.add_argument("--transparent", action="store_true", help="Use WinDivert for transparent IP-level interception (requires pydivert)")
    parser.add_argument("--memory", action="store_true", help="Read game stats directly from memory (requires pymem)")
    parser.add_argument("--ui", action="store_true", help="Start the Web Dashboard UI")
    
    args = parser.parse_args()

    hosts = None
    if args.redirect and not args.transparent:
        hosts = HostsManager(args.redirect)
        if not hosts.is_admin():
            hosts.run_as_admin()
            return
        
        choice = input(f"[?] ¿Deseas redirigir {args.redirect} a 127.0.0.1 temporalmente? [S/n]: ").lower()
        if choice in ['', 's', 'si', 'y', 'yes']:
            if not hosts.apply_redirection():
                return
            # Verify if it actually worked (anti-cheat check)
            if hosts.verify_resolution():
                print(f"[✓] Verificación DNS: {args.redirect} redirigido con éxito.")
            else:
                print(f"[!] ADVERTENCIA: {args.redirect} NO resuelve a 127.0.0.1. El Anti-Cheat podría estar bloqueando.")
        else:
            hosts = None # Don't cleanup if we didn't apply
    elif args.redirect and args.transparent:
        print("[*] Modo Transparente activo: Se ignorará la redirección por archivo hosts.")

    if args.scan:
        target = get_target_from_scan()
        if target:
            host, port, name, pid = target
            local_port = args.port if args.port is not None else port
            
            print(f"[*] DEBUG: Port detected from scan: {port}")
            print(f"[*] DEBUG: Local port decided: {local_port}")
            print(f"[*] Iniciando proxy automático para {name}...")
            print(f"[*] Objetivo: {host}:{port}")
            print(f"[*] Puerto Local (Proxy): {local_port}")
            
            proxy = MuProxy(local_port, host, port)
            
            divert = None
            if args.transparent:
                divert = DivertManager(host, port, local_port)
                if not divert.start():
                    return
                # Notify API that we are in transparent mode
                try:
                    import requests
                    requests.post("http://localhost:8000/api/config", json={"transparent": True}, timeout=1)
                except:
                    pass
            
            if args.ui:
                proxy.ui_callback = send_packet_to_ui
            
            mem = None
            if args.memory:
                mem = MemoryManager(name, pid=pid) # Use specific PID from scan
                if mem.connect():
                    mem.start_polling(callback=lambda s: asyncio.run_coroutine_threadsafe(send_memory_to_ui(s), asyncio.get_event_loop()))
                
            try:
                if args.ui:
                    print(f"[*] Dashboard disponible en: http://localhost:8000")
                    config = uvicorn.Config(app, host="127.0.0.1", port=8000, log_level="error")
                    server = uvicorn.Server(config)
                    
                    await asyncio.gather(
                        proxy.start(),
                        server.serve()
                    )
                else:
                    await proxy.start()
            except (KeyboardInterrupt, asyncio.CancelledError):
                print("\n[!] Deteniendo proxy y servidores...")
            finally:
                if divert:
                    divert.stop()
                if mem:
                    mem.stop()
                HostsManager.clear_all_redirections()
            return
        return

    local_port = args.port if args.port is not None else 55901
    print("="*50)
    print("   Mu Online Packet Decryptor & Injector Concept")
    print("="*50)
    print(f"[*] Local Port: {local_port}")
    print(f"[*] Forwarding to: {args.host}:{args.remote_port}")
    print("[*] Press Ctrl+C to stop")
    print("="*50)

    proxy = MuProxy(local_port, args.host, args.remote_port)
    if args.ui:
        proxy.ui_callback = send_packet_to_ui
    
    try:
        if args.ui:
            print(f"[*] Dashboard disponible en: http://localhost:8000")
            config = uvicorn.Config(app, host="127.0.0.1", port=8000, log_level="error")
            server = uvicorn.Server(config)
            
            await asyncio.gather(
                proxy.start(),
                server.serve()
            )
        else:
            await proxy.start()
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[!] Deteniendo proxy y servidores...")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        if 'divert' in locals() and divert:
            divert.stop()
        HostsManager.clear_all_redirections()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
