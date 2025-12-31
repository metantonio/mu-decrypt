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
        self.stats = {
            "hp": 0, "max_hp": 0, "mp": 0, "max_mp": 0, "level": 0,
            "hp_offset": 0, "max_hp_offset": 0, "mp_offset": 0, "max_mp_offset": 0, "level_offset": 0
        }
        self.thread = None
        self.on_update_callback = None
        self.candidates = [] # Stores potential addresses during a scan

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
                    print(f"[*] MEMORY DEBUG: Stats actualizadas -> {self.stats}")
                    self.on_update_callback(self.stats)
                    
            except Exception as e:
                pass # Silently handle read errors (common when game is loading)
                
            time.sleep(0.5) # Faster polling for Season 21

    def update_offsets(self, new_stats):
        """Allows updating stats externally (useful if we find offsets via Cheat Engine)"""
        self.stats.update(new_stats)

    def search_value(self, value, value_type="int"):
        """
        Initial memory scan for a specific value.
        """
        if not self.pm:
            return []
            
        self.candidates = []
        logger.info(f"[*] Escaneando memoria: Buscando {value} ({value_type})...")
        
        try:
            # We scan the main module memory regions
            # To be efficient, we iterate through readable memory pages
            import ctypes
            from pymem.ressources.structure import MEMORY_BASIC_INFORMATION
            
            address = 0
            while address < 0x7FFFFFFF: # typical 32-bit user space range
                mbi = MEMORY_BASIC_INFORMATION()
                if ctypes.windll.kernel32.VirtualQueryEx(self.pm.process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                    # Check if memory is committed, accessible, and not protected
                    if mbi.State == 0x1000 and (mbi.Protect & 0x100) == 0: # MEM_COMMIT and not PAGE_GUARD
                        # Read and check values in this region
                        try:
                            data = self.pm.read_bytes(mbi.BaseAddress, mbi.RegionSize)
                            for i in range(0, len(data) - 4, 4):
                                if value_type == "int":
                                    val = int.from_bytes(data[i:i+4], byteorder='little')
                                    if val == value:
                                        self.candidates.append(mbi.BaseAddress + i)
                                elif value_type == "float":
                                    import struct
                                    try:
                                        val = struct.unpack('f', data[i:i+4])[0]
                                        if abs(val - value) < 0.1: # Float epsilon
                                            self.candidates.append(mbi.BaseAddress + i)
                                    except: pass
                        except:
                            pass
                    address = mbi.BaseAddress + mbi.RegionSize
                else:
                    break
                    
            logger.info(f"[*] Escaneo finalizado. {len(self.candidates)} candidatos encontrados.")
            return self.candidates
        except Exception as e:
            logger.error(f"Error en escaneo: {e}")
            return []

    def filter_candidates(self, value, value_type="int"):
        """
        Filters existing scan candidates for a new value.
        """
        if not self.candidates or not self.pm:
            return []
            
        new_candidates = []
        logger.info(f"[*] Filtrando {len(self.candidates)} candidatos: Buscando {value}...")
        
        for addr in self.candidates:
            try:
                if value_type == "int":
                    if self.pm.read_int(addr) == value:
                        new_candidates.append(addr)
                elif value_type == "float":
                    if abs(self.pm.read_float(addr) - value) < 0.1:
                        new_candidates.append(addr)
            except:
                continue
                
        self.candidates = new_candidates
        logger.info(f"[*] Filtrado finalizado. Quedan {len(self.candidates)} candidatos.")
        return self.candidates

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
