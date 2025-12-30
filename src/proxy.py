import asyncio
import logging
import sys
from .packet import parse_packets

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class MuProxy:
    def __init__(self, local_port, remote_host, remote_port):
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.server = None
        self.inject_to_server_queue = asyncio.Queue()
        self.inject_to_client_queue = asyncio.Queue()
        self.auto_redirect = True # Enable automatic redirection by default

    async def handle_client(self, client_reader, client_writer):
        client_address = client_writer.get_extra_info('peername')
        logger.info(f"New connection from {client_address}")

        try:
            remote_reader, remote_writer = await asyncio.open_connection(
                self.remote_host, self.remote_port
            )
            logger.info(f"Connected to remote server {self.remote_host}:{self.remote_port}")

            # Start console command listener
            console_task = asyncio.create_task(self.console_listener())

            await asyncio.gather(
                self.pipe(client_reader, remote_writer, "CLIENT -> SERVER", self.inject_to_server_queue),
                self.pipe(remote_reader, client_writer, "SERVER -> CLIENT", self.inject_to_client_queue),
                console_task
            )
        except Exception as e:
            logger.error(f"Error handling client {client_address}: {e}")
        finally:
            client_writer.close()
            await client_writer.wait_closed()
            logger.info(f"Connection closed for {client_address}")

    async def pipe(self, reader, writer, direction, injection_queue):
        try:
            while True:
                # Use wait_for or similar to handle both reading from socket and injection queue
                # For simplicity, we check the injection queue first
                while not injection_queue.empty():
                    inj_data = await injection_queue.get()
                    logger.info(f"[{direction}] [INJECTED] {inj_data.hex()}")
                    writer.write(inj_data)
                    await writer.drain()

                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=0.1)
                except asyncio.TimeoutError:
                    continue

                if not data:
                    break
                
                # Analyze packets
                modified_data = bytearray(data)
                offset_in_data = 0
                
                for packet in parse_packets(data):
                    logger.info(f"[{direction}] {packet}")
                    logger.info(f"    HEX: {packet.raw_data.hex(' ')}")
                    
                    # Automatic Redirection Logic
                    if self.auto_redirect and direction == "SERVER -> CLIENT":
                        if packet.get_opcode() == 0xF4 and len(packet.content) > 1:
                            sub_op = packet.content[1]
                            if sub_op == 0x03: # Server Info (IP/Port)
                                # Typically: C1 [len] F4 03 [IP (16 bytes)] [Port (H)]
                                # IP starts at index 4 of raw_data
                                if len(packet.raw_data) >= 20:
                                    original_ip = packet.raw_data[4:20].split(b'\x00')[0].decode('ascii', errors='ignore')
                                    original_port = struct.unpack("<H", packet.raw_data[20:22])[0]
                                    logger.info(f"[!] INTERCEPTADO: Server Info detectado -> {original_ip}:{original_port}")
                                    
                                    # Redirect to localhost (127.0.0.1)
                                    new_ip = b"127.0.0.1\x00"
                                    new_ip = new_ip + b"\x00" * (16 - len(new_ip))
                                    
                                    # Modify the local modified_data buffer
                                    # We need to find where this packet starts in the current 'data' chunk
                                    start_idx = data.find(packet.raw_data)
                                    if start_idx != -1:
                                        modified_data[start_idx + 4 : start_idx + 20] = new_ip
                                        logger.info(f"[*] REDIRIGIDO: IP cambiada a 127.0.0.1 en el flujo de datos.")
                
                writer.write(bytes(modified_data))
                await writer.drain()
        except Exception as e:
            logger.debug(f"Pipe broken in direction {direction}: {e}")
        finally:
            writer.close()

    def inject_to_server(self, data):
        self.inject_to_server_queue.put_nowait(data)

    def inject_to_client(self, data):
        self.inject_to_client_queue.put_nowait(data)

    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_client, '127.0.0.1', self.local_port
        )
        addr = self.server.sockets[0].getsockname()
        logger.info(f"Proxy started on {addr}, forwarding to {self.remote_host}:{self.remote_port}")
        print("\n" + "="*50)
        print("   CONSOLA DE INYECCIÓN ACTIVA")
        print("   Comandos:")
        print("   - send s <hex>  : Enviar hex al SERVIDOR (ej: send s c1040001)")
        print("   - send c <hex>  : Enviar hex al CLIENTE")
        print("   - cls           : Limpiar pantalla")
        print("   - exit          : Salir")
        print("="*50 + "\n")

        async with self.server:
            await self.server.serve_forever()

    async def console_listener(self):
        loop = asyncio.get_event_loop()
        while True:
            try:
                # Read line from stdin without blocking the whole event loop
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                
                parts = line.strip().split()
                if not parts:
                    continue
                
                cmd = parts[0].lower()
                
                if cmd == "exit":
                    logger.info("Cerrando sesión de inyección...")
                    # Note: This won't stop the whole server usually without more logic
                    break
                elif cmd == "cls":
                    import os
                    os.system('cls' if os.name == 'nt' else 'clear')
                elif cmd == "send" and len(parts) >= 3:
                    target = parts[1].lower()
                    hex_data = "".join(parts[2:])
                    try:
                        data = bytes.fromhex(hex_data)
                        if target == "s":
                            self.inject_to_server(data)
                        elif target == "c":
                            self.inject_to_client(data)
                        else:
                            print("[!] Destino inválido (usa 's' o 'c')")
                    except ValueError:
                        print("[!] Formato hexadecimal inválido")
                else:
                    print(f"[*] Comando desconocido o incompleto: {line.strip()}")
            except Exception as e:
                logger.error(f"Error en consola: {e}")
                await asyncio.sleep(1)

if __name__ == "__main__":
    # Example usage (would be called from main.py)
    proxy = MuProxy(55901, "connect.muonline.com", 44405)
    asyncio.run(proxy.start())
