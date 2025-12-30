import psutil
import logging
import re
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Common Mu Online executable names
MU_EXECUTABLES = ["main.exe", "mu.exe", "play.exe", "launcher.exe"]

def find_potential_domains(file_path):
    """
    Search for domain-like strings in a binary file.
    """
    domains = set()
    if not os.path.exists(file_path):
        return []

    # Regex for domains and IPs
    domain_pattern = re.compile(rb'[a-zA-Z0-9.-]+\.(?:com|net|org|kr|br|ru|es|info|biz|me|top|xyz|link)')
    ip_pattern = re.compile(rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

    try:
        with open(file_path, 'rb') as f:
            # Read in 1MB chunks to avoid memory issues
            for chunk in iter(lambda: f.read(1024*1024), b''):
                # Search for domains
                for match in domain_pattern.findall(chunk):
                    try:
                        d = match.decode('ascii').lower()
                        if '.' in d and len(d) > 4:
                            domains.add(d)
                    except: continue
                # Search for IPs
                for match in ip_pattern.findall(chunk):
                    try:
                        ip = match.decode('ascii')
                        if ip != '127.0.0.1':
                            domains.add(ip)
                    except: continue
    except Exception as e:
        logger.error(f"Error scanning binary {file_path}: {e}")

    # Prioritize 'connect' or 'mu' related domains
    return sorted(list(domains), key=lambda x: ("connect" in x or "mu" in x), reverse=True)

def scan_game_config(exe_path):
    """
    Search for .ini, .xml, .dat files in the executable's directory.
    """
    results = set()
    game_dir = os.path.dirname(exe_path)
    if not os.path.isdir(game_dir):
        return []

    for root, _, files in os.walk(game_dir):
        for file in files:
            if file.lower().endswith(('.ini', '.xml', '.dat', '.txt', '.cfg')):
                file_path = os.path.join(root, file)
                try:
                    # Look for IP patterns in config files
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content)
                        for ip in ips:
                            if ip != '127.0.0.1': results.add(ip)
                        
                        # Look for common server-list keywords
                        domains = re.findall(r'[a-zA-Z0-9.-]+\.(?:com|net|org|kr|br)', content)
                        for d in domains: results.add(d.lower())
                except:
                    continue
        # Limit depth to game root for speed
        break
    
    return list(results)

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
                    'remote_addresses': list(set(remote_addrs)),
                    'discovered_domains': find_potential_domains(proc.info['exe'])[:5], # Top 5
                    'config_hints': scan_game_config(proc.info['exe'])[:5]
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
            
            # Highlight 44405 as ConnectServer
            remote_addrs = []
            for addr in p['remote_addresses']:
                if ":44405" in addr:
                    remote_addrs.append(f"{addr} [!!! CONNECTSERVER !!!]")
                else:
                    remote_addrs.append(addr)
            
            print(f"    Direcciones Remotas: {', '.join(remote_addrs) if remote_addrs else 'Ninguna'}")
            if p.get('discovered_domains'):
                print(f"    Dominios Sugeridos: {', '.join(p['discovered_domains'])}")
            if p.get('config_hints'):
                print(f"    Pistas en Config: {', '.join(p['config_hints'])}")
            
            if not p.get('discovered_domains') and p.get('remote_addresses'):
                print(f"    [!] TIP: No se detectaron dominios. Usa el Modo Transparente (--transparent) con estas IPs.")
            
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
