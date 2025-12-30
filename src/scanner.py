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

def print_scan_report():
    print("\n" + "="*50)
    print("   Mu Online Process & Port Scanner")
    print("="*50)
    
    processes = scan_mu_processes()
    
    if not processes:
        print("[!] No se encontraron procesos de Mu Online ejecutándose.")
        print("[*] Buscando por nombres comunes: " + ", ".join(MU_EXECUTABLES))
    else:
        for p in processes:
            print(f"[*] Proceso: {p['name']} (PID: {p['pid']})")
            print(f"    Ruta: {p['exe']}")
            print(f"    Puertos Locales Activos: {', '.join(map(str, p['ports'])) if p['ports'] else 'Ninguno'}")
            print(f"    Direcciones Remotas: {', '.join(p['remote_addresses']) if p['remote_addresses'] else 'Ninguna'}")
            print("-" * 50)
    
    print("="*50 + "\n")

if __name__ == "__main__":
    print_scan_report()
