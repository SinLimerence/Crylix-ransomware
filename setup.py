import os
import sys
import subprocess
import platform
from time import sleep

def check_admin():
    try:
        return os.getuid() == 0 if platform.system() != "Windows" else ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def install_packages():
    requirements = [
        "cryptography>=42.0.0",
        "pywin32>=306",
        "requests>=2.31.0",
        "urllib3>=2.0.0",
        "pycryptodome>=3.20.0",
        "wmi>=1.5.1",
        "setuptools>=68.0.0"
    ]

    print("[+] Installing Python dependencies...")
    try:
        subprocess.check_call([
            sys.executable, 
            "-m", 
            "pip", 
            "install", 
            "--upgrade", 
            "pip",
            "wheel"
        ])
        
        for package in requirements:
            print(f"  -> Installing {package}...")
            subprocess.check_call([
                sys.executable, 
                "-m", 
                "pip", 
                "install", 
                "--upgrade", 
                package
            ])
        
        if platform.system() == "Windows":
            print("[+] Running pywin32 post-install...")
            try:
                subprocess.check_call([
                    sys.executable,
                    os.path.join(
                        os.path.dirname(sys.executable),
                        "Scripts",
                        "pywin32_postinstall.py"
                    ),
                    "-install"
                ])
            except:
                print("  [!] PyWin32 post-install failed (may require admin)")

        print("\n[✓] All dependencies installed successfully!")
        
    except subprocess.CalledProcessError as e:
        print(f"\n[!] Installation failed: {e}")
        sys.exit(1)

def main():
    print("""
    ███████╗██████╗ ███████╗ █████╗ ██████╗ ██╗   ██╗
    ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝
    █████╗  ██████╔╝█████╗  ███████║██████╔╝ ╚████╔╝ 
    ██╔══╝  ██╔══██╗██╔══╝  ██╔══██║██╔══██╗  ╚██╔╝  
    ██║     ██║  ██║███████╗██║  ██║██║  ██║   ██║   
    ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
          Ransomware Analysis Environment Setup
    """)

    if not check_admin():
        print("[!] Warning: Some installations may require admin rights")
        sleep(2)

    install_packages()
    print("\nSetup complete. You can now run the analysis tools.")

if __name__ == "__main__":
    try:
        import ctypes
        main()
    except KeyboardInterrupt:
        print("\n[!] Setup cancelled by user")
        sys.exit(0)
