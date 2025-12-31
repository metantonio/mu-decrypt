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
            print(f"[*] Abriendo proceso Mu (PID: {self.pid or 'Auto'})...")
            if self.pid:
                self.pm = Pymem()
                self.pm.open_process_from_id(self.pid)
            else:
                self.pm = Pymem(self.process_name)
            
            print(f"[*] Proceso validado. Verificando punto de entrada (Fast Path)...")
            
            # Fast Path: Check standard Mu base addresses first to avoid Anti-Cheat hangs
            # 0x400000 is the standard for almost all 32-bit Mu Online clients
            test_addresses = [0x400000, 0x01000000]
            
            for addr in test_addresses:
                try:
                    # Check for 'MZ' header (0x5A4D)
                    header = self.pm.read_bytes(addr, 2)
                    if header == b'MZ':
                        self.base_address = addr
                        print(f"[*] Base Address verificado via MZ Header: {hex(self.base_address)}")
                        return True
                except:
                    continue

            # Fallback: If Fast Path fails, try low-level Psapi ONLY if not already found
            print("[*] MZ Header no encontrado. Intentando detección dinámica...")
            try:
                import ctypes
                from ctypes import wintypes
                Psapi = ctypes.WinDLL('Psapi.dll')
                h_modules = (wintypes.HMODULE * 1)()
                cb_needed = wintypes.DWORD()
                if Psapi.EnumProcessModules(self.pm.process_handle, ctypes.byref(h_modules), ctypes.sizeof(h_modules), ctypes.byref(cb_needed)):
                    self.base_address = h_modules[0]
                    print(f"[*] Base Address encontrado (Psapi): {hex(self.base_address)}")
                    return True
            except: pass

            # Last Resort Default
            self.base_address = 0x400000
            print(f"[!] Usando dirección por defecto: {hex(self.base_address)}")
            return True

        except Exception as e:
            print(f"[!] Error crítico conectando a la memoria: {e}")
            return False

    def start_polling(self, callback=None):
        print("[*] Iniciando hilo de monitoreo RAM...")
        self.on_update_callback = callback
        self.running = True
        self.thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.thread.start()
        print("[*] Hilo de monitoreo iniciado correctamente.")

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
        print(f"[*] Escaneando memoria: Buscando {value} ({value_type})...")
        
        try:
            import ctypes
            import struct
            from pymem.ressources.structure import MEMORY_BASIC_INFORMATION
            
            address = 0
            # Detect process architecture
            import sys
            import ctypes
            is_wow64 = ctypes.c_int()
            ctypes.windll.kernel32.IsWow64Process(self.pm.process_handle, ctypes.byref(is_wow64))
            # If is_wow64 is True, it's a 32-bit process on 64-bit OS.
            # If False and running on 64-bit Python, it's 64-bit.
            is_64bit = (struct.calcsize("P") == 8) and (is_wow64.value == 0)
            max_address = 0x7FFFFFFFFFFF if is_64bit else 0x7FFFFFFF
            
            logger.info(f"[*] Rango de escaneo: 0x0 - {hex(max_address)} (Process is {'64' if is_64bit else '32'}-bit)")
            
            region_count = 0
            while address < max_address:
                mbi = MEMORY_BASIC_INFORMATION()
                if ctypes.windll.kernel32.VirtualQueryEx(self.pm.process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                    if mbi.RegionSize <= 0: break
                    
                    # State 0x1000 = MEM_COMMIT
                    # Protect: we want readable memory, avoiding GUARD (0x100) and NOACCESS (0x01)
                    # Common readable: PAGE_READONLY (0x02), PAGE_READWRITE (0x04), PAGE_EXECUTE_READ (0x20), PAGE_EXECUTE_READWRITE (0x40)
                    is_readable = (mbi.State == 0x1000) and \
                                 (mbi.Protect & 0x101 == 0) # Not NOACCESS and Not GUARD
                                 
                    if is_readable:
                        try:
                            # Skip extremely large regions to avoid OOM
                            if mbi.RegionSize < 128 * 1024 * 1024:
                                data = self.pm.read_bytes(mbi.BaseAddress, mbi.RegionSize)
                                
                                if value_type == "int":
                                    search_pat = struct.pack('<i', int(value))
                                elif value_type == "float":
                                    search_pat = struct.pack('<f', float(value))
                                else: search_pat = None

                                if search_pat:
                                    pos = data.find(search_pat)
                                    while pos != -1:
                                        self.candidates.append(mbi.BaseAddress + pos)
                                        if len(self.candidates) > 100000: # Limit to 100k results
                                            logger.warning("[!] Demasiados resultados (>100k). Deteniendo escaneo inicial.")
                                            return self.candidates
                                        pos = data.find(search_pat, pos + 4)
                        except: pass
                    
                    address = mbi.BaseAddress + mbi.RegionSize
                    region_count += 1
                    if region_count % 500 == 0:
                        print(f"[*] Progreso de escaneo: {hex(address)} / {hex(max_address)}")
                else: break
                    
            print(f"[*] Escaneo finalizado. {len(self.candidates)} candidatos encontrados.")
            return self.candidates
        except Exception as e:
            logger.error(f"Error en escaneo: {e}")
            return []

    def write_value(self, address, value, value_type="int"):
        """
        Writes a value to a specific memory address.
        """
        if not self.pm:
            return False
            
        try:
            if value_type == "int":
                self.pm.write_int(address, int(value))
            elif value_type == "float":
                self.pm.write_float(address, float(value))
            else:
                return False
                
            logger.info(f"[*] Escrito: {value} ({value_type}) en {hex(address)}")
            return True
        except Exception as e:
            logger.error(f"[!] Error escribiendo en memoria ({hex(address)}): {e}")
            return False

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

    def discover_nearby_stats(self, anchor_address, targets):
        """
        Scans nearby memory of an anchor (e.g. Level) for other values (HP/MP).
        'targets' is a dict: {"hp": 500.0, "mp": 200.0}
        Returns a dict of discovered offsets.
        """
        if not self.pm or not self.base_address:
            return {}
            
        discovered = {}
        # Search range: ±1024 bytes around anchor
        search_start = max(0, anchor_address - 1024)
        search_end = anchor_address + 1024
        
        try:
            logger.info(f"[*] Escaneando alrededores de {hex(anchor_address)} por {targets}...")
            data = self.pm.read_bytes(search_start, 2048)
            import struct
            
            for key, target_val in targets.items():
                if target_val <= 0: continue
                
                # We look for Floats (standard for HP/MP)
                for i in range(0, len(data) - 4, 4):
                    try:
                        val = struct.unpack('f', data[i:i+4])[0]
                        if abs(val - target_val) < 1.0: # Close enough for a float
                            addr = search_start + i
                            offset = addr - self.base_address
                            discovered[key] = offset
                            logger.info(f"[*] ¡Posible {key} encontrado en offset {hex(offset)}!")
                            break # Found one, move to next target
                    except: pass
            
            return discovered
        except Exception as e:
            logger.error(f"Error en descubrimiento de estructura: {e}")
            return {}

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
