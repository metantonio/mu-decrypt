import logging
import time
import threading
import ctypes
from ctypes import wintypes
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

    def enable_debug_privilege(self):
        """
        Enables SeDebugPrivilege for the current process.
        Returns True if successful.
        """
        try:
            import ctypes
            from ctypes import wintypes

            # Constants
            SE_PRIVILEGE_ENABLED = 0x00000002
            TOKEN_ADJUST_PRIVILEGES = 0x0020
            TOKEN_QUERY = 0x0008

            # Structs
            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

            # 1. Open process token
            hToken = wintypes.HANDLE()
            if not ctypes.windll.advapi32.OpenProcessToken(
                ctypes.windll.kernel32.GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(hToken)
            ):
                return False

            # 2. Lookup LUID for SeDebugPrivilege
            luid = LUID()
            if not ctypes.windll.advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
                ctypes.windll.kernel32.CloseHandle(hToken)
                return False

            # 3. Adjust privileges
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

            if not ctypes.windll.advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None):
                err = ctypes.GetLastError()
                ctypes.windll.kernel32.CloseHandle(hToken)
                print(f"[!] AdjustTokenPrivileges falló (Error {err})")
                return False

            # Even if returns True, we must check for ERROR_NOT_ALL_ASSIGNED
            res = ctypes.GetLastError()
            if res == 0x514: # ERROR_NOT_ALL_ASSIGNED
                print("[!] SeDebugPrivilege no pudo ser asignado (No tienes permisos suficientes).")
            else:
                print("[*] SeDebugPrivilege habilitado con éxito.")

            ctypes.windll.kernel32.CloseHandle(hToken)
            return True
        except Exception as e:
            print(f"[!] Error habilitando SeDebugPrivilege: {e}")
            return False

    def is_admin(self):
        try:
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

        # Try to enable SeDebugPrivilege first
        self.enable_debug_privilege()

        try:
            print(f"[*] Abriendo proceso Mu (PID: {self.pid or 'Auto'})...")
            if self.pid:
                self.pm = Pymem()
                # Open with PROCESS_ALL_ACCESS (0x1F0FFF) for full control
                self.pm.open_process_from_id(self.pid)
            else:
                self.pm = Pymem(self.process_name)
            
            # Upgrade handle if necessary (ensure PROCESS_ALL_ACCESS)
            # This is critical for VirtualProtectEx to work
            PROCESS_ALL_ACCESS = 0x1F0FFF
            if self.pm.process_handle:
                # Try PROCESS_ALL_ACCESS first
                PROCESS_ALL_ACCESS = 0x1F0FFF
                new_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pm.process_id)
                
                if not new_handle:
                    err = ctypes.GetLastError()
                    print(f"[*] OpenProcess (ALL_ACCESS) denegado (Error {err}). Intentando permisos específicos...")
                    
                    # Fallback: Just what we need for writing
                    # VM_OPERATION (0x8) | VM_READ (0x10) | VM_WRITE (0x20) | QUERY_INFORMATION (0x400)
                    SPECIFIC_RIGHTS = 0x8 | 0x10 | 0x20 | 0x400
                    new_handle = ctypes.windll.kernel32.OpenProcess(SPECIFIC_RIGHTS, False, self.pm.process_id)
                
                if new_handle:
                    print(f"[*] Handle de proceso mejorado obtenido con éxito.")
                    
                    # Rights Audit
                    try:
                        flags = wintypes.DWORD()
                        if ctypes.windll.kernel32.GetHandleInformation(new_handle, ctypes.byref(flags)):
                            print(f"[*] Información del Handle: {flags.value}")
                    except: pass

                    ctypes.windll.kernel32.CloseHandle(self.pm.process_handle)
                    self.pm.process_handle = new_handle
                else:
                    err = ctypes.GetLastError()
                    print(f"[!] Falló la adquisición del handle con permisos de escritura (Error {err}).")
                    print("[!] Este es un bloqueo de nivel Driver (Anti-Cheat). Intentaremos bypass quirúrgico durante la escritura.")
            
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
        Writes a value to a specific memory address with surgical handle fallback.
        """
        if not self.pm:
            return False
            
        try:
            import struct
            # size and buffer for direct WriteProcessMemory
            if value_type == "int":
                data = struct.pack("<i", int(value))
                size = 4
            elif value_type == "float":
                data = struct.pack("<f", float(value))
                size = 4
            else:
                return False
            
            # --- PHASE 1: Try with current handle ---
            success = self._perform_raw_write(self.pm.process_handle, address, data, size, value, value_type)
            
            # --- PHASE 2: Surgical Bypass (If Phase 1 failed with Access Denied) ---
            if not success:
                err = ctypes.GetLastError()
                if err == 5: # Access Denied
                    logger.info(f"[*] Acceso denegado con handle principal. Intentando bypass con handle quirúrgico...")
                    
                    # Minimal rights: Just VM_WRITE and VM_OPERATION
                    MINIMAL_WRITE_RIGHTS = 0x20 | 0x08
                    temp_handle = ctypes.windll.kernel32.OpenProcess(MINIMAL_WRITE_RIGHTS, False, self.pm.process_id)
                    
                    if temp_handle:
                        success = self._perform_raw_write(temp_handle, address, data, size, value, value_type, "Quirúrgico")
                        ctypes.windll.kernel32.CloseHandle(temp_handle)
                    else:
                        logger.error(f"[!] No se pudo obtener ni siquiera un handle quirúrgico (Error {ctypes.GetLastError()})")
            
            return success

        except Exception as e:
            logger.error(f"[!] Excepción en write_value ({hex(address)}): {e}")
            return False

    def _perform_raw_write(self, handle, address, data, size, value, value_type, label="Principal"):
        """
        Internal helper with NT-level bypass and stealth logic.
        """
        if not handle:
            return False

        # 0. Diagnostic Audit & Selective Protection
        needs_protect = True
        try:
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]
            
            mbi = MEMORY_BASIC_INFORMATION()
            if ctypes.windll.kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                logger.info(f"[*] Audit RAM ({label}) @ {hex(address)}: State={hex(mbi.State)}, Protect={hex(mbi.Protect)}")
                # 0x04 = PAGE_READWRITE, 0x40 = PAGE_EXECUTE_READWRITE
                if mbi.Protect in [0x04, 0x40]:
                    needs_protect = False
                    logger.debug(f"[*] Página ya es escribible ({hex(mbi.Protect)}). Omitiendo VirtualProtect.")
        except: pass

        # 1. Protection (Only if needed)
        old_protect = wintypes.DWORD()
        vp_success = False
        if needs_protect:
            PAGE_READWRITE = 0x04
            vp_success = ctypes.windll.kernel32.VirtualProtectEx(
                handle, 
                ctypes.c_void_p(address), 
                size, 
                PAGE_READWRITE, 
                ctypes.byref(old_protect)
            )
            if not vp_success:
                logger.error(f"[!] VirtualProtectEx ({label}) falló: Error {ctypes.GetLastError()}")

        # 2. NT-Level Write: Direct Syscall to ntdll
        # This bypasses hooks in kernel32.WriteProcessMemory
        bytes_written = ctypes.c_size_t(0)
        try:
            # NTSTATUS NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG)
            nt_status = ctypes.windll.ntdll.NtWriteVirtualMemory(
                handle,
                ctypes.c_void_p(address),
                data,
                size,
                ctypes.byref(bytes_written)
            )
            write_success = (nt_status == 0) # STATUS_SUCCESS
            if not write_success:
                logger.error(f"[!] NtWriteVirtualMemory ({label}) falló: NTSTATUS {hex(nt_status & 0xffffffff)}")
        except Exception as e:
            logger.error(f"[!] Error llamando a ntdll: {e}")
            write_success = False

        # 3. Restore protection
        if vp_success:
            ctypes.windll.kernel32.VirtualProtectEx(
                handle, 
                ctypes.c_void_p(address), 
                size, 
                old_protect, 
                ctypes.byref(old_protect)
            )

        if write_success:
            logger.info(f"[*] ¡BYPASS NT ÉXITO! Escrito ({label}): {value} ({value_type}) en {hex(address)}")
            return True
        else:
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
