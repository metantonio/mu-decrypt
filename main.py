import asyncio
import argparse
import sys
from src.proxy import MuProxy
from src.scanner import print_scan_report, get_target_from_scan
from src.hosts_manager import HostsManager

async def main():
    parser = argparse.ArgumentParser(description="Mu Online Packet Decryptor & Injector")
    parser.add_argument("--port", type=int, default=55901, help="Local port to listen on")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Remote server host (default: 127.0.0.1)")
    parser.add_argument("--remote-port", type=int, default=44405, help="Remote server port (default: 44405)")
    parser.add_argument("--scan", action="store_true", help="Scan for Mu Online processes and ports")
    parser.add_argument("--redirect", type=str, help="Domain to redirect to localhost (requires admin)")
    
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
            print(f"[*] Iniciando proxy automático para {name}...")
            print(f"[*] Objetivo: {host}:{port}")
            proxy = MuProxy(args.port, host, port)
            try:
                await proxy.start()
            except KeyboardInterrupt:
                print("\n[!] Deteniendo proxy...")
            finally:
                if hosts:
                    hosts.remove_redirection()
            return
        return

    print("="*50)
    print("   Mu Online Packet Decryptor & Injector Concept")
    print("="*50)
    print(f"[*] Local Port: {args.port}")
    print(f"[*] Forwarding to: {args.host}:{args.remote_port}")
    print("[*] Press Ctrl+C to stop")
    print("="*50)

    proxy = MuProxy(args.port, args.host, args.remote_port)
    
    try:
        await proxy.start()
    except KeyboardInterrupt:
        print("\n[!] Stopping proxy...")
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
