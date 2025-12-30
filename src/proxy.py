import asyncio
import logging
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

    async def handle_client(self, client_reader, client_writer):
        client_address = client_writer.get_extra_info('peername')
        logger.info(f"New connection from {client_address}")

        try:
            remote_reader, remote_writer = await asyncio.open_connection(
                self.remote_host, self.remote_port
            )
            logger.info(f"Connected to remote server {self.remote_host}:{self.remote_port}")

            await asyncio.gather(
                self.pipe(client_reader, remote_writer, "CLIENT -> SERVER", self.inject_to_server_queue),
                self.pipe(remote_reader, client_writer, "SERVER -> CLIENT", self.inject_to_client_queue)
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
                for packet in parse_packets(data):
                    logger.info(f"[{direction}] {packet}")
                
                writer.write(data)
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

        async with self.server:
            await self.server.serve_forever()

if __name__ == "__main__":
    # Example usage (would be called from main.py)
    proxy = MuProxy(55901, "connect.muonline.com", 44405)
    asyncio.run(proxy.start())
