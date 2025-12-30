import asyncio
import argparse
import sys
from src.proxy import MuProxy
from src.scanner import print_scan_report, get_target_from_scan
from src.hosts_manager import HostsManager
from src.fast_server import app, send_packet_to_ui, get_command_for_proxy
import uvicorn

async def main():
    parser = argparse.ArgumentParser(description="Mu Online Packet Decryptor & Injector")
    parser.add_argument("--port", type=int, default=None, help="Local port to listen on (default: matches remote port if --scan is used, otherwise 55901)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Remote server host (default: 127.0.0.1)")
    parser.add_argument("--remote-port", type=int, default=44405, help="Remote server port (default: 44405)")
    parser.add_argument("--scan", action="store_true", help="Scan for Mu Online processes and ports")
    parser.add_argument("--redirect", type=str, help="Domain to redirect to localhost (requires admin)")
    parser.add_argument("--ui", action="store_true", help="Start the Web Dashboard UI")
    
    args = parser.parse_args()

    hosts = None
    if args.redirect:
        hosts = HostsManager(args.redirect)
        if not hosts.is_admin():
            hosts.run_as_admin()
            return
        
        choice = input(f"[?] ¿Deseas redirigir {args.redirect} a 127.0.0.1 temporalmente? [S/n]: ").lower()
        if choice in ['', 's', 'si', 'y', 'yes']:
            if not hosts.apply_redirection():
                return
        else:
            hosts = None # Don't cleanup if we didn't apply

    if args.scan:
        target = get_target_from_scan()
        if target:
            host, port, name = target
            local_port = args.port if args.port is not None else port
            
            print(f"[*] DEBUG: Port detected from scan: {port}")
            print(f"[*] DEBUG: Local port decided: {local_port}")
            print(f"[*] Iniciando proxy automático para {name}...")
            print(f"[*] Objetivo: {host}:{port}")
            print(f"[*] Puerto Local (Proxy): {local_port}")
            
            proxy = MuProxy(local_port, host, port)
            
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
            finally:
                if hosts:
                    hosts.remove_redirection()
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
        if hosts:
            hosts.remove_redirection()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
