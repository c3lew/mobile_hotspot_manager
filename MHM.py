#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
MHM.py - Mobile Hotspot Manager PyInstaller Script
This script compiles the hotspot_manager_gui.py into an executable file using PyInstaller.
It ensures all necessary files (including the PowerShell script) are included in the package.
"""

import os
import sys
import subprocess
import shutil
from datetime import datetime

def main():
    print("=" * 80)
    print("Mobile Hotspot Manager - PyInstaller Build Script")
    print("=" * 80)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Working directory: {os.getcwd()}")
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("PyInstaller is not installed. Installing it now...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
            print("PyInstaller installed successfully.")
        except Exception as e:
            print(f"Failed to install PyInstaller: {e}")
            return 1
    
    # Define paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    gui_script = os.path.join(script_dir, "hotspot_manager_gui.py")
    ps_script = os.path.join(script_dir, "mobile-hotspot-manager.ps1")
    icon_path = os.path.join(script_dir, "wifi_icon.ico")
    
    # Check if required files exist
    if not os.path.exists(gui_script):
        print(f"Error: GUI script not found at {gui_script}")
        return 1
    
    if not os.path.exists(ps_script):
        print(f"Error: PowerShell script not found at {ps_script}")
        return 1
    
    # Check if icon exists (optional)
    icon_option = []
    if os.path.exists(icon_path):
        print(f"Icon found at {icon_path}")
        icon_option = ["--icon", icon_path]
    else:
        print("Icon file not found. Continuing without an icon.")
    
    # Build the PyInstaller command
    pyinstaller_cmd = [
        "pyinstaller",
        "--name=MobileHotspotManager",
        "--onefile",  # Create a single executable
        "--windowed",  # Don't show console window when running the app
        "--clean",     # Clean PyInstaller cache before building
        "--add-data", f"{ps_script};.",  # Include the PowerShell script
    ]
    
    # Add icon if available
    if icon_option:
        pyinstaller_cmd.extend(icon_option)
    
    # Add the main script
    pyinstaller_cmd.append(gui_script)
    
    print("\nRunning PyInstaller with the following command:")
    print(" ".join(pyinstaller_cmd))
    print("\nThis may take a few minutes...\n")
    
    # Run PyInstaller
    try:
        subprocess.check_call(pyinstaller_cmd)
        print("\nPyInstaller completed successfully!")
        
        # Check if the executable was created
        dist_dir = os.path.join(script_dir, "dist")
        exe_path = os.path.join(dist_dir, "MobileHotspotManager.exe")
        
        if os.path.exists(exe_path):
            print(f"Executable created at: {exe_path}")
            
            # Copy the executable to the script directory for convenience
            shutil.copy(exe_path, script_dir)
            print(f"Executable copied to: {os.path.join(script_dir, 'MobileHotspotManager.exe')}")
            
            print("\nBuild completed successfully!")
            print("You can now run MobileHotspotManager.exe to start the application.")
        else:
            print(f"Error: Executable not found at {exe_path}")
            return 1
        
    except Exception as e:
        print(f"Error during PyInstaller execution: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())