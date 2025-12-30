import logging
import time
import threading
try:
    from pymem import Pymem
    from pymem.process import module_from_name
except ImportError:
    Pymem = None

logger = logging.getLogger(__name__)

class MemoryManager:
    def __init__(self, process_name="main.exe", pid=None):
        self.process_name = process_name
        self.pid = pid
        self.pm = None
        self.base_address = None
        self.running = False
        self.stats = {"hp": 0, "max_hp": 0, "mp": 0, "max_mp": 0, "level": 0}
        self.thread = None
        self.on_update_callback = None

    def is_admin(self):
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def connect(self):
        if Pymem is None:
            logger.error("[!] Pymem no está instalado. Ejecuta 'pip install pymem'.")
            return False
            
        if not self.is_admin():
            logger.error("[!] Error: Mu-Decrypt debe ejecutarse como ADMINISTRADOR para leer la memoria.")
            return False

        try:
            self.pm = Pymem()
            if self.pid:
                self.pm.open_process_from_id(self.pid)
                logger.info(f"[*] Conectado a la memoria de {self.process_name} (PID: {self.pid})")
            else:
                self.pm.open_process_from_name(self.process_name)
                logger.info(f"[*] Conectado a la memoria de {self.process_name}")
            
            module = module_from_name(self.pm.process_handle, self.process_name)
            self.base_address = module.lpBaseOfDll
            logger.info(f"[*] Base Address: {hex(self.base_address)}")
            return True
        except Exception as e:
            logger.error(f"[!] Error conectando a la memoria: {e}")
            return False

    def start_polling(self, callback=None):
        self.on_update_callback = callback
        self.running = True
        self.thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)

    def _poll_loop(self):
        """
        Main loop for reading memory. 
        Uses the 'stats' dictionary as a source for offsets.
        """
        while self.running:
            if not self.pm:
                break
                
            try:
                # We read values if the offset is non-zero
                # Season 21 usually uses float for HP/MP and Int for Level
                for key in ["hp", "max_hp", "mp", "max_mp"]:
                    offset = self.stats.get(f"{key}_offset", 0)
                    if offset > 0:
                        self.stats[key] = int(self.pm.read_float(self.base_address + offset))
                
                level_offset = self.stats.get("level_offset", 0)
                if level_offset > 0:
                    self.stats["level"] = self.pm.read_int(self.base_address + level_offset)

                if self.on_update_callback:
                    self.on_update_callback(self.stats)
                    
            except Exception as e:
                pass # Silently handle read errors (common when game is loading)
                
            time.sleep(0.5) # Faster polling for Season 21

    def update_offsets(self, new_stats):
        """Allows updating stats externally (useful if we find offsets via Cheat Engine)"""
        self.stats.update(new_stats)

    def find_addresses_by_value(self, value, size=4):
        """
        Scans memory for a specific value. Useful to find 'Level'.
        Returns a list of addresses.
        """
        if not self.pm:
            return []
            
        import pymem.memory
        found_addresses = []
        try:
            # We scan the main module memory
            process_handle = self.pm.process_handle
            # Simple scan (might be slow for whole RAM, but good for main module)
            # This is a simplified version of a pattern scan
            # In a real scenario, we'd use self.pm.pattern_scan_all
            logger.info(f"[*] Escaneando memoria por el valor: {value}...")
            # For now, we suggest the user to use Cheat Engine to find the base 
            # and we will focus on pointer resolution once we have the anchor.
            pass
        except Exception as e:
            logger.error(f"Error escaneando: {e}")
        return found_addresses

    def read_at_offset(self, offset, type="int"):
        if not self.base_address or not self.pm:
            return None
        try:
            addr = self.base_address + offset
            if type == "int":
                return self.pm.read_int(addr)
            elif type == "float":
                return self.pm.read_float(addr)
            elif type == "short":
                return self.pm.read_short(addr)
        except:
            return None
