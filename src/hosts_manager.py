import os
import sys
import ctypes
import logging
import socket

logger = logging.getLogger(__name__)

HOSTS_PATH = r'C:\Windows\System32\drivers\etc\hosts'
MARKER = "# [Mu-Decrypt Redirection]"

class HostsManager:
    def __init__(self, domain, target_ip="127.0.0.1"):
        self.domain = domain
        self.target_ip = target_ip
        self.entry = f"{target_ip} {domain} {MARKER}\n"
        self.original_content = None

    @staticmethod
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def run_as_admin(self):
        """ Re-runs the script with admin privileges if needed """
        if self.is_admin():
            return True
        
        print("[!] Este comando requiere privilegios de ADMINISTRADOR para editar el archivo 'hosts'.")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        return False

    def apply_redirection(self):
        if not self.is_admin():
            print("[!] ERROR: No se pudo aplicar la redirección. Lanza el script como ADMINISTRADOR.")
            return False

        try:
            with open(HOSTS_PATH, 'r') as f:
                lines = f.readlines()
            
            # Check if already exists
            if any(MARKER in line and self.domain in line for line in lines):
                print(f"[*] La redirección para {self.domain} ya existe en el archivo hosts.")
                return True

            with open(HOSTS_PATH, 'a') as f:
                f.write(self.entry)
            
            print(f"[+] Redirección aplicada con éxito: {self.domain} -> {self.target_ip}")
            return True
        except Exception as e:
            logger.error(f"Error al escribir en hosts: {e}")
            return False

    def remove_redirection(self):
        if not self.is_admin():
            return False

        try:
            with open(HOSTS_PATH, 'r') as f:
                lines = f.readlines()

            new_lines = [line for line in lines if MARKER not in line]

            if len(new_lines) == len(lines):
                return True

            with open(HOSTS_PATH, 'w') as f:
                f.writelines(new_lines)
            
            print(f"[-] Redirección eliminada y archivo hosts restaurado.")
            return True
        except Exception as e:
            print(f"[!] Error al limpiar hosts: {e}")
            return False

    @staticmethod
    def clear_all_redirections():
        """
        Removes all entries from the hosts file that have the MARKER.
        """
        if not HostsManager.is_admin():
            logger.warning("[!] No se pueden limpiar los hosts: Sin privilegios de administrador.")
            return False

        try:
            with open(HOSTS_PATH, 'r') as f:
                lines = f.readlines()

            new_lines = [line for line in lines if MARKER not in line]

            if len(new_lines) == len(lines):
                return True

            with open(HOSTS_PATH, 'w') as f:
                f.writelines(new_lines)
            
            print(f"[-] Todos los dominios redirigidos han sido restaurados.")
            return True
        except Exception as e:
            logger.error(f"Error al limpiar archivo hosts: {e}")
            return False

    def verify_resolution(self):
        """
        Check if the domain resolves to the target status.
        Returns True if redirected correctly, False otherwise.
        """
        try:
            resolved_ip = socket.gethostbyname(self.domain)
            success = resolved_ip == self.target_ip
            if success:
                logger.info(f"[✓] Verificación DNS: {self.domain} resuelve correctamente a {resolved_ip}")
            else:
                logger.warning(f"[!] Verificación DNS FALLIDA: {self.domain} resuelve a {resolved_ip} (se esperaba {self.target_ip}).")
                logger.warning("    Esto indica que el juego o un anti-cheat está ignorando el archivo 'hosts'.")
            return success
        except Exception as e:
            logger.error(f"Error verificando resolución DNS: {e}")
            return False
