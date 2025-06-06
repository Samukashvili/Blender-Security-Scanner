import os

def execute_commands():
    os.system('powershell -WindowStyle Hidden -Command Get-Process')
    exec('print("malicious code")')