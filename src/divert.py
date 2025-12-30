import pydivert
import threading
import logging
import time
import os

logger = logging.getLogger(__name__)

class DivertManager:
    """
    Manages network-level redirection using WinDivert.
    It intercepts packets going to the REMOTE_IP:REMOTE_PORT and redirects them to 127.0.0.1:LOCAL_PORT.
    It also handles the return packets so the source IP remains consistent for the application.
    """
    def __init__(self, remote_ip, remote_port, local_port):
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.local_port = local_port
        self.handle = None
        self.thread = None
        self.running = False

    def start(self):
        """
        Starts the interception thread.
        Filter traps: 
        1. Outbound packets to RemoteIP:RemotePort (Redirect to 127.0.0.1:LocalPort)
        2. Inbound packets from 127.0.0.1:LocalPort (Redirect back to RemoteIP:RemotePort)
        """
        # Filter for TCP packets to/from the target
        # We exclude the proxy's outbound connection (SourcePort 54321) to avoid infinite loops
        # and also exclude common loopback noise.
        filter_str = (
            f"(tcp.DstPort == {self.remote_port} and ip.DstAddr == {self.remote_ip} and tcp.SrcPort != 54321) or "
            f"(tcp.SrcPort == {self.local_port} and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1)"
        )
        
        try:
            print(f"[*] DEBUG Filter WinDivert: {filter_str}")
            self.handle = pydivert.WinDivert(filter_str)
            self.handle.open()
            self.running = True
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()
            logger.info(f"[*] Interceptor WinDivert activo para {self.remote_ip}:{self.remote_port} -> 127.0.0.1:{self.local_port}")
            return True
        except Exception as e:
            logger.error(f"[!] Error al iniciar WinDivert: {e}")
            print(f"[!] Error: No se pudo iniciar WinDivert. ¿Tienes privilegios de Administrador?")
            return False

    def _run(self):
        count = 0
        while self.running:
            try:
                packet = self.handle.recv()
                
                # Rule 1: Outbound to Remote -> Local Proxy
                if packet.dst_addr == self.remote_ip and packet.dst_port == self.remote_port:
                    packet.dst_addr = "127.0.0.1"
                    packet.dst_port = self.local_port
                    count += 1
                
                # Rule 2: Inbound from Local Proxy -> Fake Remote
                elif packet.src_addr == "127.0.0.1" and packet.src_port == self.local_port:
                    packet.src_addr = self.remote_ip
                    packet.src_port = self.remote_port
                    count += 1
                
                if count % 10 == 0 and count > 0:
                    logger.info(f"[*] WinDivert: {count} paquetes procesados...")

                self.handle.send(packet)
            except Exception as e:
                if self.running:
                    logger.error(f"Error en buceo WinDivert: {e}")
                break

    def stop(self):
        self.running = False
        if self.handle:
            self.handle.close()
        logger.info("[-] Interceptor WinDivert detenido.")
