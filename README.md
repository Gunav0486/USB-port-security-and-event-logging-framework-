

USB Port Security and Event Logging Framework

A Zero Trust USB Port Security System designed to monitor, authenticate, and control USB access in real-time. This Python-based framework enhances endpoint security by enforcing multi-factor authentication, blocking unauthorized devices, and logging every event for traceability.

Features

Real-time USB monitoring and access control

Immediate USB blocking upon insertion

GUI-based employee authentication with OTP verification

Event logging in MySQL database

Whitelist/blacklist support for USB devices

Breach detection and USB isolation

Persistent background monitoring

Professional customtkinter interface


Requirements

Operating System: Windows (Admin rights required)

Python Version: Python 3.8 or above

Python Dependencies:

pip install bcrypt pymysql customtkinter pywin32 psutil wmi


Folder Structure

.
├── usb_security.py              # Main script
├── config.json                  # Configuration for DB and email
├── blacklist.json               # Stores blacklisted USB IDs
├── whitelist.json               # Stores whitelisted USB IDs

Configuration

Create a config.json file in the root directory with the following structure:

{
  "db_host": "localhost",
  "db_user": "your_db_username",
  "db_pass": "your_db_password",
  "email_sender": "your_email@example.com",
  "email_password": "your_email_app_password",
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587
}

Make sure your MySQL server has an appropriate database (employee_db) and logging table (usb_logs).

How to Connect and Run

1. Run with Administrator Privileges

The script modifies USB registry entries and requires admin access. Right-click Command Prompt and choose Run as Administrator, then execute:

python usb_security.py

If not started as administrator, the program will relaunch itself with elevated privileges automatically.

2. Insert USB Device

A GUI will appear for employee login and email verification.

After validating credentials, an OTP will be sent to the email.

On successful OTP entry, the USB device will be unblocked.


3. Manual USB Blocking

After device usage, click “Block USB” in the GUI to re-enable protection. This resets the system to its secure default state.

Security and Logging

Unauthorized USBs are blocked immediately.

All authentication attempts and device events are logged into the database.

Blacklisted devices are permanently disabled and logged.



