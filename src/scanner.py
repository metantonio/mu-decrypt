import psutil
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Common Mu Online executable names
MU_EXECUTABLES = ["main.exe", "mu.exe", "play.exe", "launcher.exe"]

def scan_mu_processes():
    """
    Scans for Mu Online processes and returns a list of dictionaries with info.
    """
    found_processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = proc.info['name'].lower()
            if any(mu_name in name for mu_name in MU_EXECUTABLES):
                connections = proc.connections(kind='tcp')
                ports = [conn.laddr.port for conn in connections if conn.status == 'ESTABLISHED']
                remote_addrs = [f"{conn.raddr.ip}:{conn.raddr.port}" for conn in connections if conn.raddr]
                
                found_processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'exe': proc.info['exe'],
                    'ports': list(set(ports)),
                    'remote_addresses': list(set(remote_addrs))
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
    return found_processes

def print_scan_report(processes=None):
    if processes is None:
        processes = scan_mu_processes()

    print("\n" + "="*50)
    print("   Mu Online Process & Port Scanner")
    print("="*50)
    
    if not processes:
        print("[!] No se encontraron procesos de Mu Online ejecutándose.")
        print("[*] Buscando por nombres comunes: " + ", ".join(MU_EXECUTABLES))
    else:
        for idx, p in enumerate(processes):
            print(f"[{idx}] Proceso: {p['name']} (PID: {p['pid']})")
            print(f"    Ruta: {p['exe']}")
            print(f"    Puertos Locales Activos: {', '.join(map(str, p['ports'])) if p['ports'] else 'Ninguno'}")
            print(f"    Direcciones Remotas: {', '.join(p['remote_addresses']) if p['remote_addresses'] else 'Ninguna'}")
            print("-" * 50)
    
    print("="*50 + "\n")
    return processes

def get_target_from_scan():
    processes = scan_mu_processes()
    if not processes:
        print_scan_report(processes)
        return None
    
    print_scan_report(processes)
    
    targets = []
    for p in processes:
        for addr in p['remote_addresses']:
            if ":" in addr:
                ip, port = addr.split(":")
                targets.append((ip, int(port), p['name']))
    
    if not targets:
        print("[!] Proceso encontrado, pero no hay conexiones remotas activas para interceptar.")
        return None
    
    if len(targets) == 1:
        target = targets[0]
        choice = input(f"[?] Se detectó una conexión activa ({target[0]}:{target[1]}). ¿Iniciar proxy? [S/n]: ").lower()
        if choice in ['', 's', 'si', 'y', 'yes']:
            return target
    else:
        print("[*] Múltiples conexiones detectadas:")
        for idx, t in enumerate(targets):
            print(f"    {idx}: {t[0]}:{t[1]} ({t[2]})")
        
        try:
            choice = input(f"[?] Selecciona el índice para iniciar el proxy (o presiona Enter para cancelar): ")
            if choice.strip() == "":
                return None
            return targets[int(choice)]
        except:
            return None
    
    return None

if __name__ == "__main__":
    print_scan_report()
