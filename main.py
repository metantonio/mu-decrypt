import asyncio
import argparse
import sys
from src.proxy import MuProxy

async def main():
    parser = argparse.ArgumentParser(description="Mu Online Packet Decryptor & Injector")
    parser.add_argument("--port", type=int, default=55901, help="Local port to listen on")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Remote server host (default: 127.0.0.1)")
    parser.add_argument("--remote-port", type=int, default=44405, help="Remote server port (default: 44405)")
    
    args = parser.parse_args()

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

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
