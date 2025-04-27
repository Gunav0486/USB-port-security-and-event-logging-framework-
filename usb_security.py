import tkinter as tk
from tkinter import messagebox
import subprocess
import random
import smtplib
import pymysql
import bcrypt
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time
import pythoncom
import wmi
import datetime
import platform
import json
import os
import customtkinter as ctk
import ctypes
import re
import threading
import winreg
import sys
import win32con
import win32gui
import win32process
import psutil

# Global variables
otp_container = [None]
otp_timestamp = [None]
usb_blocked = False
auth_in_progress = False
monitoring_active = True
failed_attempts = {}
MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 300
OTP_EXPIRY = 300
DELAY_BETWEEN_ATTEMPTS = 2
after_id = None
triggering_usb_instance_id = [None]
credentials = None
blacklist = []
blacklisted_vids_pids = set(["2E8A_0003", "239A_80F4"])
whitelisted_vids_pids = set()
PROCESS_NAME = "python.exe"
CONFIG_FILE = "config.json"
BLACKLIST_FILE = "blacklist.json"
WHITELIST_FILE = "whitelist.json"
auth_window = None
last_insertion_time = [0]
auth_lock = threading.Lock()
breach_detected = [False]
last_block_time = [0]

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run_as_admin():
    if not is_admin():
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run as admin: {e}")

def hide_console():
    try:
        hwnd = win32gui.GetForegroundWindow()
        if hwnd:
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            process = psutil.Process(pid)
            process_name = process.name().lower()
            if "cmd.exe" in process_name or "powershell.exe" in process_name:
                win32gui.ShowWindow(hwnd, win32con.SW_HIDE)
    except Exception:
        pass

def load_config():
    try:
        if not os.path.exists(CONFIG_FILE):
            raise FileNotFoundError(f"Configuration file {CONFIG_FILE} not found")
        with open(CONFIG_FILE, "r") as config_file:
            return json.load(config_file)
    except Exception as e:
        sys.exit(1)

def load_blacklist():
    global blacklist, blacklisted_vids_pids
    try:
        if not os.path.exists(BLACKLIST_FILE):
            blacklisted_vids_pids = set(["2E8A_0003", "239A_80F4"])
            return list(blacklisted_vids_pids)
        with open(BLACKLIST_FILE, "r") as blacklist_file:
            data = json.load(blacklist_file)
            blacklist = data.get("blacklisted_devices", [])
            blacklisted_vids_pids = set(blacklist)
            blacklisted_vids_pids.add("2E8A_0003")
            blacklisted_vids_pids.add("239A_80F4")
            return blacklist
    except Exception:
        blacklisted_vids_pids = set(["2E8A_0003", "239A_80F4"])
        return list(blacklisted_vids_pids)

def load_whitelist():
    global whitelisted_vids_pids
    try:
        if not os.path.exists(WHITELIST_FILE):
            return []
        with open(WHITELIST_FILE, "r") as whitelist_file:
            data = json.load(whitelist_file)
            whitelisted_vids_pids = set(data.get("whitelisted_devices", []))
            return list(whitelisted_vids_pids)
    except Exception:
        return []

def log_event(employee_id, action, credentials, device_id=None, breach_details=None):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    system_info = f"{platform.system()} {platform.release()} - {platform.node()}"
    
    main_events = ["Auth Request", "Auth Granted", "Auth Unsuccessful", "Breach Detected", "USB Blocked", "USB Unblocked", "Authentication Successful"]
    if action not in main_events or credentials is None:
        return
    
    try:
        connection = pymysql.connect(
            host=credentials["db_host"],
            user=credentials["db_user"],
            password=credentials["db_pass"],
            database="employee_db",
            cursorclass=pymysql.cursors.DictCursor
        )
        with connection.cursor() as cursor:
            query = """
                INSERT INTO usb_logs (employee_id, action, timestamp, device_id, system_info, breach_details)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            values = (employee_id, action, timestamp, device_id, system_info, breach_details)
            cursor.execute(query, values)
            connection.commit()
    except pymysql.Error:
        pass
    finally:
        if 'connection' in locals():
            connection.close()

def disable_hid_driver(vid_pid):
    try:
        key_path = r"SYSTEM\CurrentControlSet\Enum\HID"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    if vid_pid.upper() in subkey_name.upper():
                        subkey_path = f"{key_path}\\{subkey_name}"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_ALL_ACCESS) as subkey:
                            j = 0
                            while True:
                                try:
                                    subsubkey_name = winreg.EnumKey(subkey, j)
                                    device_key_path = f"{subkey_path}\\{subsubkey_name}"
                                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_key_path, 0, winreg.KEY_ALL_ACCESS) as device_key:
                                        winreg.SetValueEx(device_key, "ConfigFlags", 0, winreg.REG_DWORD, 0x1)
                                    j += 1
                                except OSError:
                                    break
                    i += 1
                except OSError:
                    break
        subprocess.run("devcon rescan", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception:
        pass

def disable_hid_device(instance_id):
    try:
        command = f"pnputil /disable-device \"{instance_id}\""
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0
    except Exception:
        return False

def removeusb_device_fast(instance_id, vid_pid):
    if vid_pid in whitelisted_vids_pids:
        return True

    if vid_pid in blacklisted_vids_pids:
        isolate_system(instance_id, vid_pid)
        disable_hid_driver(vid_pid)
        if disable_hid_device(instance_id):
            pass
        usb_command = f"devcon remove \"{instance_id}\""
        try:
            subprocess.run(usb_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    return True

def persistent_hid_remover():
    while monitoring_active:
        for vid_pid in blacklisted_vids_pids:
            try:
                hid_command = f"devcon find \"HID\\*\" | findstr /i \"{vid_pid}\""
                result = subprocess.run(hid_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.stdout:
                    for line in result.stdout.splitlines():
                        if "HID Keyboard Device" in line:
                            hid_instance_id = line.split(":")[0].strip()
                            delete_command = f"devcon remove \"{hid_instance_id}\""
                            subprocess.run(delete_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                            isolate_system(hid_instance_id, vid_pid)
            except Exception:
                pass
        time.sleep(0.001)

def watchdog():
    script_path = os.path.abspath(__file__)
    while True:
        running_instances = 0
        current_pid = os.getpid()
        for p in psutil.process_iter(['pid', 'name', 'cmdline']):
            if p.info['name'] == PROCESS_NAME and p.info['pid'] != current_pid:
                try:
                    if script_path in ' '.join(p.info['cmdline']):
                        running_instances += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        if running_instances == 0:
            subprocess.Popen([sys.executable, script_path], creationflags=subprocess.CREATE_NO_WINDOW)
            time.sleep(1)
        elif running_instances > 1:
            sys.exit(0)
        time.sleep(5)

def isolate_system(instance_id, vid_pid):
    global monitoring_active, auth_in_progress, triggering_usb_instance_id, breach_detected
    def disable_network():
        subprocess.run("netsh interface set interface \"Ethernet\" admin=disable", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run("netsh interface set interface \"Wi-Fi\" admin=disable", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def disable_related_devices():
        command = f"pnputil /enum-devices | findstr /i \"{vid_pid}\""
        result = subprocess.run(["powershell", "-Command", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.splitlines():
                if "Instance ID" in line:
                    related_id = line.split(":", 1)[1].strip()
                    disable_usb_device(related_id)

    def block_usb_storage():
        global usb_blocked
        if not usb_blocked:
            run_silent("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 4")
            run_silent("devcon restart *USB*")
            run_silent("devcon rescan")
            usb_blocked = True

    log_event(None, "Breach Detected", credentials, vid_pid, f"Blacklisted device detected: {vid_pid}")
    threads = [threading.Thread(target=disable_network, daemon=True),
               threading.Thread(target=disable_related_devices, daemon=True),
               threading.Thread(target=block_usb_storage, daemon=True)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    monitoring_active = False
    auth_in_progress = False
    triggering_usb_instance_id[0] = None
    breach_detected[0] = True

def run_silent(command):
    try:
        result = subprocess.run(["powershell", "-Command", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        return result.returncode == 0
    except Exception:
        return False

def disable_usb_device(device_id):
    command = f"pnputil /disable-device \"{device_id}\""
    return run_silent(command)

def generate_otp():
    otp = random.randint(100000, 999999)
    otp_container[0] = otp
    otp_timestamp[0] = time.time()
    return otp

def get_otp_remaining_time():
    if otp_timestamp[0] is None:
        return 0
    elapsed_time = time.time() - otp_timestamp[0]
    remaining = OTP_EXPIRY - elapsed_time
    return max(0, int(remaining))

def verify_credentials(employee_id, password, credentials):
    log_event(employee_id, "Auth Request", credentials, triggering_usb_instance_id[0])
    
    if employee_id in failed_attempts:
        last_attempt_time = failed_attempts[employee_id].get('last_attempt', 0)
        if failed_attempts[employee_id]['count'] >= MAX_ATTEMPTS:
            if time.time() - last_attempt_time < LOCKOUT_DURATION:
                log_event(employee_id, "Auth Unsuccessful", credentials, triggering_usb_instance_id[0])
                return False
            else:
                failed_attempts[employee_id] = {'count': 0, 'last_attempt': 0}

    try:
        connection = pymysql.connect(
            host=credentials["db_host"],
            user=credentials["db_user"],
            password=credentials["db_pass"],
            database="employee_db",
            cursorclass=pymysql.cursors.DictCursor
        )
        with connection.cursor() as cursor:
            cursor.execute("SELECT employee_password FROM employees WHERE employee_id = %s", (employee_id,))
            result = cursor.fetchone()
        connection.close()
        
        if result and bcrypt.checkpw(password.encode('utf-8'), result['employee_password'].encode('utf-8')):
            if employee_id in failed_attempts:
                del failed_attempts[employee_id]
            return True
        else:
            if employee_id not in failed_attempts:
                failed_attempts[employee_id] = {'count': 0, 'last_attempt': 0}
            failed_attempts[employee_id]['count'] += 1
            failed_attempts[employee_id]['last_attempt'] = time.time()
            log_event(employee_id, "Auth Unsuccessful", credentials, triggering_usb_instance_id[0])
            time.sleep(DELAY_BETWEEN_ATTEMPTS)
            return False
    except pymysql.Error:
        return False

def get_employee_email(employee_id, credentials):
    try:
        connection = pymysql.connect(
            host=credentials["db_host"],
            user=credentials["db_user"],
            password=credentials["db_pass"],
            database="employee_db",
            cursorclass=pymysql.cursors.DictCursor
        )
        with connection.cursor() as cursor:
            cursor.execute("SELECT employee_email FROM employees WHERE employee_id = %s", (employee_id,))
            result = cursor.fetchone()
        connection.close()
        return result['employee_email'] if result else None
    except pymysql.Error:
        return None

def send_otp_email(sender_email, sender_password, smtp_server, smtp_port, recipient_email, otp):
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = recipient_email
    message['Subject'] = 'Your OTP Code'
    body = f'Your OTP code is: {otp} (Valid for {OTP_EXPIRY//60} minutes)'
    message.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, message.as_string())
        server.quit()
        messagebox.showinfo("Success", "OTP sent to your email!")
        return otp
    except smtplib.SMTPException:
        return None

def show_loading_window(root, action):
    loading_window = tk.Toplevel(root)
    loading_window.title("Processing")
    loading_window.geometry("250x100")
    loading_window.configure(bg="#0A0A0A")
    loading_window.overrideredirect(True)
    
    loading_window.update_idletasks()
    width = loading_window.winfo_width()
    height = loading_window.winfo_height()
    x = (loading_window.winfo_screenwidth() // 2) - (width // 2)
    y = (loading_window.winfo_screenheight() // 2) - (height // 2)
    loading_window.geometry(f'+{x}+{y}')
    
    tk.Label(loading_window, text=f"{action} USB...\nPlease wait", 
             font=("Arial", 12), fg="cyan", bg="#0A0A0A").pack(pady=20)
    
    dots = tk.Label(loading_window, text="...", font=("Arial", 12), fg="cyan", bg="#0A0A0A")
    dots.pack()
    
    def animate():
        current = dots['text']
        dots['text'] = current + "." if len(current) < 6 else "."
        loading_window.after(300, animate)
    
    animate()
    return loading_window

def block_usb(root):
    global usb_blocked, last_block_time
    if usb_blocked:
        return
    loading_window = show_loading_window(root, "Blocking")
    root.update()
    
    success = run_silent("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 4")
    if not success:
        loading_window.destroy()
        return
    time.sleep(1)
    
    success &= run_silent("devcon restart *USB*")
    success &= run_silent("devcon rescan")
    
    usb_blocked = success
    last_block_time[0] = time.time()
    time.sleep(2)
    loading_window.destroy()
    if success:
        log_event(None, "USB Blocked", credentials)

def unblock_usb(root, employee_id, credentials):
    global usb_blocked, auth_in_progress, monitoring_active, after_id
    loading_window = show_loading_window(root, "Unblocking")
    root.update()
    
    success = run_silent("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 3")
    if not success:
        loading_window.destroy()
        return
    time.sleep(1)
    
    success &= run_silent("devcon restart *USB*")
    success &= run_silent("devcon rescan")
    
    if success:
        usb_blocked = False
        monitoring_active = False
        if after_id:
            root.after_cancel(after_id)
        log_event(employee_id, "Authentication Successful", credentials, triggering_usb_instance_id[0])
        log_event(employee_id, "Auth Granted", credentials, triggering_usb_instance_id[0])
        log_event(employee_id, "USB Unblocked", credentials, triggering_usb_instance_id[0])
        messagebox.showinfo("Success", "USB storage unblocked successfully")
        messagebox.showinfo("Ready", "System is ready to use")
    time.sleep(2)
    loading_window.destroy()
    auth_in_progress = False
    show_block_usb_gui(root, credentials, employee_id)

def show_block_usb_gui(root, credentials, employee_id):
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    block_gui = ctk.CTkToplevel(root)
    block_gui.title("Block USB")
    block_gui.geometry("300x150")
    block_gui.resizable(False, False)
    block_gui.protocol("WM_DELETE_WINDOW", lambda: None)

    block_gui.update_idletasks()
    width = block_gui.winfo_width()
    height = block_gui.winfo_height()
    x = (block_gui.winfo_screenwidth() // 2) - (width // 2)
    y = (block_gui.winfo_screenheight() // 2) - (height // 2)
    block_gui.geometry(f'+{x}+{y}')

    main_frame = ctk.CTkFrame(master=block_gui, corner_radius=15, fg_color="#1E1E1E")
    main_frame.pack(pady=20, padx=20, fill="both", expand=True)

    title_label = ctk.CTkLabel(master=main_frame, text="Block USB Storage", font=("Roboto", 14, "bold"), text_color="#FFFFFF")
    title_label.pack(pady=10)

    def block_and_restart_monitoring():
        global monitoring_active, triggering_usb_instance_id
        block_usb(root)
        triggering_usb_instance_id[0] = None
        monitoring_active = True
        block_gui.destroy()
        log_event(employee_id, "USB Blocked", credentials, triggering_usb_instance_id[0])
        time.sleep(3)
        monitor_usb(root, credentials)

    block_button = ctk.CTkButton(master=main_frame, text="Block USB", font=("Roboto", 14, "bold"), 
                                 fg_color="#D32F2F", hover_color="#B71C1C", corner_radius=10, height=40, 
                                 command=block_and_restart_monitoring)
    block_button.pack(pady=20)

    def glow_button(button, on=True):
        button.configure(border_color="#00BCD4" if on else "#D32F2F", border_width=2 if on else 1)

    block_button.bind("<Enter>", lambda e: glow_button(block_button, True))
    block_button.bind("<Leave>", lambda e: glow_button(block_button, False))

def extract_vid_pid(instance_id):
    try:
        match = re.search(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", instance_id, re.IGNORECASE)
        if match:
            vid, pid = match.groups()
            return f"{vid}_{pid}".upper()
        return None
    except Exception:
        return None

def get_instance_id(event):
    try:
        dependent = getattr(event, "Dependent", None)
        if not dependent:
            return "Unknown"
        
        dependent_str = str(dependent)
        device_id_match = re.search(r'DeviceID="([^"]+)"', dependent_str)
        if device_id_match:
            return device_id_match.group(1)
        
        return getattr(dependent, "DeviceID", None) or getattr(dependent, "PNPDeviceID", None) or "Unknown"
    except Exception:
        return "Unknown"

def monitor_usb_removal(instance_id_to_monitor):
    global auth_in_progress, triggering_usb_instance_id, auth_window
    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        watcher_remove = c.Win32_USBControllerDevice.watch_for("deletion")
        while auth_in_progress and triggering_usb_instance_id[0] == instance_id_to_monitor:
            try:
                event_remove = watcher_remove(timeout_ms=50)
                if event_remove:
                    removed_id = get_instance_id(event_remove)
                    if removed_id == instance_id_to_monitor:
                        if auth_window and auth_window.winfo_exists():
                            auth_window.destroy()
                        auth_in_progress = False
                        triggering_usb_instance_id[0] = None
                        log_event(None, "Auth Unsuccessful", credentials, removed_id)
                        messagebox.showwarning("Authentication Failed", "USB removed before authentication completed.")
                        break
            except wmi.x_wmi:
                pass
            time.sleep(0.01)
    except Exception:
        pass
    finally:
        pythoncom.CoUninitialize()

def monitor_usb(root, credentials):
    global auth_in_progress, monitoring_active, after_id, triggering_usb_instance_id, auth_window, last_insertion_time, last_block_time
    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        watcher_insert = c.Win32_USBControllerDevice.watch_for("creation")
    except Exception:
        pythoncom.CoUninitialize()
        return

    for vid_pid in blacklisted_vids_pids:
        disable_hid_driver(vid_pid)

    def check_existing_devices():
        for device in c.Win32_USBControllerDevice():
            instance_id = get_instance_id(device)
            vid_pid = extract_vid_pid(instance_id)
            if vid_pid and vid_pid in blacklisted_vids_pids and vid_pid not in whitelisted_vids_pids:
                pass

    check_existing_devices()
    threading.Thread(target=persistent_hid_remover, daemon=True).start()

    def check_usb():
        global auth_in_progress, monitoring_active, after_id, triggering_usb_instance_id, auth_window, last_insertion_time, last_block_time
        if not monitoring_active:
            pythoncom.CoUninitialize()
            return

        try:
            event_insert = watcher_insert(timeout_ms=50)
            if event_insert:
                current_time = time.time()
                if current_time - last_block_time[0] < 5:
                    after_id = root.after(1000, check_usb)
                    return
                if current_time - last_insertion_time[0] < 2:
                    after_id = root.after(1000, check_usb)
                    return
                
                instance_id = get_instance_id(event_insert)
                vid_pid = extract_vid_pid(instance_id)
                last_insertion_time[0] = current_time
                
                if vid_pid and vid_pid in blacklisted_vids_pids and vid_pid not in whitelisted_vids_pids:
                    removeusb_device_fast(instance_id, vid_pid)
                    messagebox.showwarning("Breach Detected", f"Blacklisted device detected: {vid_pid}")
                    after_id = root.after(1000, check_usb)
                    return
                
                with auth_lock:
                    if not auth_in_progress and (not auth_window or not auth_window.winfo_exists()) and not breach_detected[0]:
                        auth_in_progress = True
                        triggering_usb_instance_id[0] = instance_id
                        if auth_window and auth_window.winfo_exists():
                            auth_window.destroy()
                        removal_thread = threading.Thread(target=monitor_usb_removal, args=(instance_id,), daemon=True)
                        removal_thread.start()
                        employee_id, success = prompt_authentication(root, credentials)
                        if success:
                            unblock_usb(root, employee_id, credentials)
                            return
                        else:
                            auth_in_progress = False
                            triggering_usb_instance_id[0] = None
                    after_id = root.after(1000, check_usb)
                    return
        except wmi.x_wmi:
            pass
        except Exception:
            pass
        
        after_id = root.after(1000, check_usb)

    after_id = root.after(1000, check_usb)

def prompt_authentication(root, credentials):
    global auth_in_progress, auth_window
    auth_result = [False]
    employee_id_holder = [None]
    last_otp_request = {}

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    auth_window = ctk.CTkToplevel(root)
    auth_window.title("USB Authentication")
    auth_window.geometry("450x550")
    auth_window.resizable(False, False)
    auth_window.protocol("WM_DELETE_WINDOW", lambda: None)

    auth_window.update_idletasks()
    width = auth_window.winfo_width()
    height = auth_window.winfo_height()
    x = (auth_window.winfo_screenwidth() // 2) - (width // 2)
    y = (auth_window.winfo_screenheight() // 2) - (height // 2)
    auth_window.geometry(f'+{x}+{y}')

    auth_window.attributes("-alpha", 0.0)

    def fade_in(step=0.05):
        current_alpha = auth_window.attributes("-alpha")
        if current_alpha < 1.0 and auth_window.winfo_exists():
            auth_window.attributes("-alpha", current_alpha + step)
            auth_window.after(30, fade_in)

    auth_window.after(100, fade_in)

    main_frame = ctk.CTkFrame(master=auth_window, corner_radius=15, fg_color="#1E1E1E")
    main_frame.pack(pady=20, padx=20, fill="both", expand=True)

    title_label = ctk.CTkLabel(master=main_frame, text="USB Authentication", font=("Roboto", 24, "bold"), text_color="#FFFFFF")
    title_label.pack(pady=(30, 20))

    emp_id_frame = ctk.CTkFrame(master=main_frame, fg_color="transparent")
    emp_id_frame.pack(fill="x", padx=20, pady=5)
    emp_id_label = ctk.CTkLabel(master=emp_id_frame, text="Employee ID", font=("Roboto", 14), text_color="#CCCCCC")
    emp_id_label.pack(anchor="w")
    emp_id_entry = ctk.CTkEntry(master=emp_id_frame, font=("Roboto", 14), fg_color="#2E2E2E", border_color="#4A4A4A", 
                                text_color="#E0E0E0", placeholder_text="Enter Employee ID", corner_radius=10, height=40)
    emp_id_entry.pack(fill="x", pady=(2, 10))

    pass_frame = ctk.CTkFrame(master=main_frame, fg_color="transparent")
    pass_frame.pack(fill="x", padx=20, pady=5)
    pass_label = ctk.CTkLabel(master=pass_frame, text="Password", font=("Roboto", 14), text_color="#CCCCCC")
    pass_label.pack(anchor="w")
    pass_entry = ctk.CTkEntry(master=pass_frame, font=("Roboto", 14), fg_color="#2E2E2E", border_color="#4A4A4A", 
                              text_color="#E0E0E0", placeholder_text="Enter Password", show="*", corner_radius=10, height=40)
    pass_entry.pack(fill="x", pady=(2, 10))

    otp_frame = ctk.CTkFrame(master=main_frame, fg_color="transparent")
    otp_frame.pack(fill="x", padx=20, pady=5)
    otp_label = ctk.CTkLabel(master=otp_frame, text="OTP", font=("Roboto", 14), text_color="#CCCCCC")
    otp_label.pack(anchor="w")
    otp_entry = ctk.CTkEntry(master=otp_frame, font=("Roboto", 14), fg_color="#2E2E2E", border_color="#4A4A4A", 
                             text_color="#E0E0E0", placeholder_text="Enter OTP", corner_radius=10, height=40)
    otp_entry.pack(fill="x", pady=(2, 10))

    def glow_entry(entry, on=True):
        entry.configure(border_color="#00BCD4" if on else "#4A4A4A", border_width=2 if on else 1)

    emp_id_entry.bind("<FocusIn>", lambda e: glow_entry(emp_id_entry, True))
    emp_id_entry.bind("<FocusOut>", lambda e: glow_entry(emp_id_entry, False))
    pass_entry.bind("<FocusIn>", lambda e: glow_entry(pass_entry, True))
    pass_entry.bind("<FocusOut>", lambda e: glow_entry(pass_entry, False))
    otp_entry.bind("<FocusIn>", lambda e: glow_entry(otp_entry, True))
    otp_entry.bind("<FocusOut>", lambda e: glow_entry(otp_entry, False))

    timer_label = ctk.CTkLabel(master=main_frame, text="OTP Time Remaining: N/A", font=("Roboto", 12), text_color="#FFCA28")
    timer_label.pack(pady=10)

    status_label = ctk.CTkLabel(master=main_frame, text="", font=("Roboto", 12), text_color="#FF5733")
    status_label.pack(pady=5)

    def update_timer():
        if otp_timestamp[0] is not None and auth_window.winfo_exists():
            remaining = get_otp_remaining_time()
            minutes, seconds = divmod(remaining, 60)
            timer_label.configure(text=f"OTP Time Remaining: {minutes:02d}:{seconds:02d}")
            if remaining > 0:
                auth_window.after(1000, update_timer)
            else:
                timer_label.configure(text="OTP Expired")
                otp_container[0] = None
                otp_timestamp[0] = None
                status_label.configure(text="OTP has expired. Request a new one.")

    def send_otp():
        employee_id = emp_id_entry.get()
        employee_id_holder[0] = employee_id
        
        if not employee_id or not pass_entry.get():
            status_label.configure(text="Please enter Employee ID and Password")
            return

        if employee_id in failed_attempts and failed_attempts[employee_id]['count'] >= MAX_ATTEMPTS:
            remaining = int(LOCKOUT_DURATION - (time.time() - failed_attempts[employee_id]['last_attempt']))
            status_label.configure(text=f"Account locked. Wait {remaining}s")
            return

        current_time = time.time()
        last_request = last_otp_request.get(employee_id, 0)
        if current_time - last_request < 60:
            remaining = int(60 - (current_time - last_request))
            status_label.configure(text=f"Wait {remaining}s before requesting another OTP")
            return

        password = pass_entry.get()
        
        if verify_credentials(employee_id, password, credentials):
            email = get_employee_email(employee_id, credentials)
            if email:
                otp = generate_otp()
                result = send_otp_email(credentials["email_user"], credentials["email_pass"], 
                                       credentials["smtp_server"], credentials["smtp_port"], email, otp)
                if result:
                    last_otp_request[employee_id] = time.time()
                    send_button.configure(state="disabled")
                    auth_window.after(60000, lambda: send_button.configure(state="normal") if auth_window.winfo_exists() else None)
                    status_label.configure(text="OTP sent. Check your email.")
                    update_timer()
                else:
                    status_label.configure(text="Failed to send OTP. Try again.")
            else:
                status_label.configure(text="No email found for this ID")
        else:
            attempts_left = MAX_ATTEMPTS - (failed_attempts.get(employee_id, {'count': 0})['count'])
            status_label.configure(text=f"Invalid credentials. {attempts_left} attempts left")

    def verify_otp():
        global auth_in_progress
        employee_id = employee_id_holder[0]
        entered_otp = otp_entry.get().strip()

        if not entered_otp:
            status_label.configure(text="Please enter an OTP")
            return

        remaining = get_otp_remaining_time()
        if remaining <= 0 or otp_container[0] is None:
            status_label.configure(text="OTP has expired. Request a new one.")
            otp_container[0] = None
            otp_timestamp[0] = None
            return

        if str(otp_container[0]) == entered_otp:
            auth_result[0] = True
            auth_in_progress = False
            status_label.configure(text="OTP verified successfully!")
            log_event(employee_id, "Authentication Successful", credentials, triggering_usb_instance_id[0])
            auth_window.destroy()
        else:
            status_label.configure(text="Invalid OTP. Try again.")

    button_frame = ctk.CTkFrame(master=main_frame, fg_color="transparent")
    button_frame.pack(fill="x", padx=20, pady=20)

    def glow_button(button, on=True):
        button.configure(border_color="#00BCD4" if on else "#1976D2" if button.cget("text") == "Send OTP" else "#388E3C", 
                        border_width=2 if on else 1)

    send_button = ctk.CTkButton(master=button_frame, text="Send OTP", font=("Roboto", 14, "bold"), fg_color="#1976D2", 
                                hover_color="#1565C0", corner_radius=10, height=40, command=lambda: [click_feedback(send_button), send_otp()])
    send_button.pack(side="left", padx=5, fill="x", expand=True)
    send_button.bind("<Enter>", lambda e: glow_button(send_button, True))
    send_button.bind("<Leave>", lambda e: glow_button(send_button, False))

    verify_button = ctk.CTkButton(master=button_frame, text="Verify OTP", font=("Roboto", 14, "bold"), fg_color="#388E3C", 
                                  hover_color="#2E7D32", corner_radius=10, height=40, command=lambda: [click_feedback(verify_button), verify_otp()])
    verify_button.pack(side="right", padx=5, fill="x", expand=True)
    verify_button.bind("<Enter>", lambda e: glow_button(verify_button, True))
    verify_button.bind("<Leave>", lambda e: glow_button(verify_button, False))

    def click_feedback(button):
        button.configure(fg_color="#0288D1" if button.cget("text") == "Send OTP" else "#1B5E20")
        auth_window.after(100, lambda: button.configure(fg_color="#1976D2" if button.cget("text") == "Send OTP" else "#388E3C") if auth_window.winfo_exists() else None)

    while auth_window.winfo_exists() and auth_in_progress:
        root.update()
        time.sleep(0.01)
    
    return employee_id_holder[0], auth_result[0]

def register_task():
    exe_path = os.path.abspath(__file__)
    task_name = "USB_Security"
    command = f'schtasks /create /tn "{task_name}" /tr "\"{sys.executable}\" \"{exe_path}\"" /sc onstart /ru SYSTEM /rl highest /f'
    try:
        subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception:
        pass

def main():
    global credentials, blacklist, root
    
    run_as_admin()
    hide_console()
    register_task()

    credentials = load_config()
    blacklist = load_blacklist()
    load_whitelist()

    root = tk.Tk()
    root.withdraw()
    
    time.sleep(2)
    block_usb(root)
    monitor_usb(root, credentials)
    
    root.mainloop()

if __name__ == "__main__":
    main()