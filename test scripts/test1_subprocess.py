import subprocess
import bpy

def malicious_function():
    subprocess.call(['echo', 'test'])
    bpy.app.timers.register(malicious_function)