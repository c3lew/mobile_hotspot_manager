import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import os
import threading
import re
import sys
from datetime import datetime

class HotspotManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Mobile Hotspot Manager")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        # Set icon (if available)
        try:
            self.root.iconbitmap("wifi_icon.ico")
        except:
            pass  # Icon not found, continue without it
            
        # Configure style
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Segoe UI", 10))
        self.style.configure("TLabel", font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))
        self.style.configure("Status.TLabel", font=("Segoe UI", 10))
        self.style.configure("Success.TLabel", foreground="green")
        self.style.configure("Error.TLabel", foreground="red")
        self.style.configure("Warning.TLabel", foreground="orange")
        
        # Variables
        self.current_status = tk.StringVar(value="Unknown")
        self.is_running = False
        self.script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mobile-hotspot-manager.ps1")
        
        # Create UI
        self.create_widgets()
        
        # Check if script exists
        if not os.path.exists(self.script_path):
            messagebox.showerror("Error", f"PowerShell script not found at:\n{self.script_path}")
            self.disable_controls()
        else:
            # Get initial status
            self.update_status()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(title_frame, text="Mobile Hotspot Manager", 
                               font=("Segoe UI", 16, "bold"))
        title_label.pack(side=tk.LEFT)
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Hotspot Status", padding="10")
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_label = ttk.Label(status_frame, textvariable=self.current_status,
                                     font=("Segoe UI", 12))
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        self.refresh_button = ttk.Button(status_frame, text="Refresh", 
                                        command=self.update_status)
        self.refresh_button.pack(side=tk.RIGHT)
        
        # Control frame
        control_frame = ttk.LabelFrame(main_frame, text="Hotspot Controls", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X)
        
        self.enable_button = ttk.Button(button_frame, text="Enable Hotspot", 
                                      command=lambda: self.run_action("Enable"))
        self.enable_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        self.disable_button = ttk.Button(button_frame, text="Disable Hotspot", 
                                       command=lambda: self.run_action("Disable"))
        self.disable_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        self.toggle_button = ttk.Button(button_frame, text="Toggle Hotspot", 
                                      command=lambda: self.run_action("Toggle"))
        self.toggle_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        
        self.get_wifi_button = ttk.Button(button_frame, text="Get WiFi Passwords", 
                                        command=lambda: self.run_action("GetWiFi"))
        self.get_wifi_button.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        
        self.get_hotspot_button = ttk.Button(button_frame, text="Get Hotspot Credentials", 
                                           command=lambda: self.run_action("GetHotspot"))
        self.get_hotspot_button.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        self.help_button = ttk.Button(button_frame, text="Show Help", 
                                    command=lambda: self.run_action("Help"))
        self.help_button.grid(row=1, column=2, padx=5, pady=5, sticky="ew")
        
        # Configure grid columns to be equal width
        for i in range(3):
            button_frame.columnconfigure(i, weight=1)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        # Output text area
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, 
                                                   font=("Consolas", 10))
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Progress indicator
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, 
                                      length=100, mode='indeterminate',
                                      variable=self.progress_var)
        self.progress.pack(fill=tk.X, pady=(5, 0))
        
        # Status bar
        self.status_bar = ttk.Label(main_frame, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, pady=(5, 0))
    
    def update_status(self):
        """Update the current hotspot status"""
        self.run_action("Status", update_only=True)
    
    def run_action(self, action, update_only=False):
        """Run the PowerShell script with the specified action"""
        if self.is_running:
            messagebox.showinfo("Info", "A command is already running. Please wait.")
            return
        
        # Start a new thread to run the command
        threading.Thread(target=self._run_action_thread, 
                        args=(action, update_only), 
                        daemon=True).start()
    
    def _run_action_thread(self, action, update_only=False):
        """Thread function to run the PowerShell script"""
        self.is_running = True
        
        # Update UI
        if not update_only:
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Running command: {action}...\n\n")
        
        self.status_bar.config(text=f"Running {action}...")
        self.progress.start(10)
        
        # Disable buttons while running
        self.disable_controls()
        
        try:
            # Build command
            cmd = [
                "powershell.exe",
                "-ExecutionPolicy", "Bypass",
                "-File", self.script_path,
                "-Action", action
            ]
            
            # Run command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Process output
            for line in process.stdout:
                if not update_only:
                    self.output_text.insert(tk.END, line)
                    self.output_text.see(tk.END)
                    self.root.update_idletasks()
                
                # Check for status information
                if "Mobile Hotspot Status:" in line:
                    status_match = re.search(r"Mobile Hotspot Status: (\w+)", line)
                    if status_match:
                        status = status_match.group(1)
                        self.current_status.set(status)
                        self.update_status_label(status)
            
            # Get return code
            return_code = process.wait()
            
            # Process any errors
            error_output = process.stderr.read()
            if error_output:
                if not update_only:
                    self.output_text.insert(tk.END, f"\nERROR:\n{error_output}\n")
                    self.output_text.see(tk.END)
            
            # Update status bar
            if return_code == 0:
                self.status_bar.config(text=f"Command {action} completed successfully")
            else:
                self.status_bar.config(text=f"Command {action} failed with code {return_code}")
            
            # If this was a status update, check the output for the status
            if action == "Status" and update_only:
                self.parse_status_from_log()
            
        except Exception as e:
            if not update_only:
                self.output_text.insert(tk.END, f"\nERROR: {str(e)}\n")
                self.output_text.see(tk.END)
            self.status_bar.config(text=f"Error: {str(e)}")
        
        finally:
            # Re-enable buttons
            self.enable_controls()
            self.progress.stop()
            self.is_running = False
    
    def parse_status_from_log(self):
        """Parse the status from the log file if we couldn't get it from stdout"""
        try:
            log_dir = os.path.dirname(self.script_path)
            today = datetime.now().strftime('%Y-%m-%d')
            log_file = os.path.join(log_dir, f"MobileHotspot_{today}.log")
            
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    
                # Look for status lines from the end of the file
                for line in reversed(lines):
                    if "Current mobile hotspot status:" in line:
                        status_match = re.search(r"Current mobile hotspot status: (\w+)", line)
                        if status_match:
                            status = status_match.group(1)
                            self.current_status.set(status)
                            self.update_status_label(status)
                            break
        except Exception as e:
            print(f"Error parsing log file: {e}")
    
    def update_status_label(self, status):
        """Update the status label with appropriate styling"""
        if status.lower() == "on" or status.lower() == "enabled":
            self.status_label.configure(style="Success.TLabel")
            self.current_status.set("ENABLED")
        elif status.lower() == "off" or status.lower() == "disabled":
            self.status_label.configure(style="Error.TLabel")
            self.current_status.set("DISABLED")
        else:
            self.status_label.configure(style="Warning.TLabel")
            self.current_status.set(status.upper())
    
    def disable_controls(self):
        """Disable all control buttons"""
        self.enable_button.configure(state=tk.DISABLED)
        self.disable_button.configure(state=tk.DISABLED)
        self.toggle_button.configure(state=tk.DISABLED)
        self.get_wifi_button.configure(state=tk.DISABLED)
        self.get_hotspot_button.configure(state=tk.DISABLED)
        self.help_button.configure(state=tk.DISABLED)
        self.refresh_button.configure(state=tk.DISABLED)
    
    def enable_controls(self):
        """Enable all control buttons"""
        self.enable_button.configure(state=tk.NORMAL)
        self.disable_button.configure(state=tk.NORMAL)
        self.toggle_button.configure(state=tk.NORMAL)
        self.get_wifi_button.configure(state=tk.NORMAL)
        self.get_hotspot_button.configure(state=tk.NORMAL)
        self.help_button.configure(state=tk.NORMAL)
        self.refresh_button.configure(state=tk.NORMAL)

def main():
    root = tk.Tk()
    app = HotspotManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()