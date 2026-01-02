import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import time
import os
from datetime import datetime

class IPBlocker:
    def __init__(self, root):
        self.root = root
        self.root.title("🔥 HACKERAI - IP NETWORK BLOCKER")
        self.root.geometry("900x700")
        self.root.configure(bg="#0a0a0a")
        self.root.resizable(False, False)
        
        self.blocked_ips = set()
        self.is_blocking = False
        
        self.setup_hacker_gui()
    
    def setup_hacker_gui(self):
        # Header
        header = tk.Label(self.root, text="🔥 IP NETWORK BLOCKER v2.0", 
                         font=('Courier', 20, 'bold'), fg='#ff4444', bg='#0a0a0a')
        header.pack(pady=10)
        
        # Input Frame
        input_frame = tk.Frame(self.root, bg='#0a0a0a')
        input_frame.pack(pady=10, padx=20, fill='x')
        
        tk.Label(input_frame, text="🎯 Target IP / Range:", font=('Courier', 14), 
                fg='#00ff00', bg='#0a0a0a').pack(anchor='w')
        
        self.ip_entry = tk.Entry(input_frame, font=('Courier', 12), width=30, 
                               bg='#1a1a1a', fg='#00ff00', insertbackground='#00ff00')
        self.ip_entry.pack(pady=5, fill='x')
        self.ip_entry.insert(0, "192.168.1.0/24")  # Example subnet
        
        # Buttons Frame
        btn_frame = tk.Frame(self.root, bg='#0a0a0a')
        btn_frame.pack(pady=20)
        
        self.block_btn = tk.Button(btn_frame, text="🚫 BLOCK NETWORK", 
                                 command=self.start_blocking, bg='#ff4444', fg='white',
                                 font=('Courier', 14, 'bold'), relief='flat', 
                                 padx=30, pady=10, height=2)
        self.block_btn.pack(side=tk.LEFT, padx=10)
        
        self.unblock_btn = tk.Button(btn_frame, text="✅ UNBLOCK ALL", 
                                   command=self.stop_blocking, bg='#00ff44', fg='black',
                                   font=('Courier', 14, 'bold'), relief='flat',
                                   padx=30, pady=10, height=2, state='disabled')
        self.unblock_btn.pack(side=tk.LEFT, padx=10)
        
        # Status Frame
        status_frame = tk.Frame(self.root, bg='#0a0a0a')
        status_frame.pack(pady=10, padx=20, fill='x')
        
        self.status_label = tk.Label(status_frame, text="🟢 READY - Enter IP Range", 
                                   font=('Courier', 12, 'bold'), fg='#00ff00', bg='#0a0a0a')
        self.status_label.pack()
        
        # Terminal Log
        log_frame = tk.Frame(self.root, bg='#0a0a0a')
        log_frame.pack(pady=10, padx=20, fill='both', expand=True)
        
        tk.Label(log_frame, text="📡 TERMINAL LOG", font=('Courier', 14, 'bold'),
                fg='#ffaa00', bg='#0a0a0a').pack(anchor='w')
        
        self.log = scrolledtext.ScrolledText(log_frame, bg='#000', fg='#0f0',
                                           font=('Courier', 11), height=15,
                                           insertbackground='#0f0')
        self.log.pack(fill='both', expand=True, pady=5)
        
        # Blocked IPs List
        list_frame = tk.Frame(self.root, bg='#0a0a0a')
        list_frame.pack(pady=10, padx=20, fill='x')
        
        tk.Label(list_frame, text="🚫 BLOCKED IPS", font=('Courier', 12, 'bold'),
                fg='#ff4444', bg='#0a0a0a').pack(anchor='w')
        
        self.blocked_listbox = tk.Listbox(list_frame, bg='#1a1a1a', fg='#ff4444',
                                        font=('Courier', 10), height=4)
        self.blocked_listbox.pack(fill='x', pady=5)
    
    def log_msg(self, msg, color='white'):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log.see(tk.END)
        self.root.update()
    
    def get_ip_range(self, ip_range):
        """Convert CIDR to IP list"""
        import ipaddress
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except:
            return [ip_range]  # Single IP
    
    def block_ip_windows(self, ip):
        """Windows - Add to firewall (Admin required)"""
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=Block_{ip}", f"dir=in", f"action=block", f"remoteip={ip}"
            ], check=True, capture_output=True)
            return True
        except:
            return False
    
    def block_ip_linux(self, ip):
        """Linux - iptables block"""
        try:
            subprocess.run([
                "sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"
            ], check=True, capture_output=True)
            return True
        except:
            return False
    
    def unblock_ip_windows(self, ip):
        subprocess.run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name=Block_{ip}"
        ], capture_output=True)
    
    def unblock_all_windows(self):
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=all"], 
                      capture_output=True)
    
    def start_blocking(self):
        ip_input = self.ip_entry.get().strip()
        if not ip_input:
            messagebox.showerror("Error", "Enter IP or range (192.168.1.0/24)")
            return
        
        # Thread blocking to avoid GUI freeze
        threading.Thread(target=self._block_thread, args=(ip_input,), daemon=True).start()
    
    def _block_thread(self, ip_input):
        self.is_blocking = True
        self.block_btn.config(state='disabled')
        self.unblock_btn.config(state='normal')
        self.status_label.config(text="🔴 BLOCKING ACTIVE", fg='#ff4444')
        
        self.log_msg(f"🚫 Blocking range: {ip_input}")
        ips = self.get_ip_range(ip_input)
        
        for ip in ips[:50]:  # Limit to 50 for performance
            if not self.is_blocking:
                break
                
            if self.block_ip_windows(ip) or self.block_ip_linux(ip):
                self.blocked_ips.add(ip)
                self.blocked_listbox.insert(tk.END, ip)
                self.log_msg(f"✅ BLOCKED: {ip}")
            else:
                self.log_msg(f"❌ FAILED: {ip} (Run as Admin)", "#ffaa00")
            
            time.sleep(0.1)  # Rate limit
        
        self.log_msg(f"🎉 BLOCKING COMPLETE: {len(self.blocked_ips)} IPs")
    
    def stop_blocking(self):
        self.is_blocking = False
        self.block_btn.config(state='normal')
        self.unblock_btn.config(state='disabled')
        self.status_label.config(text="🟢 READY", fg='#00ff00')
        
        self.log_msg("✅ UNBLOCKING ALL IPS...")
        
        # Windows unblock
        self.unblock_all_windows()
        
        self.blocked_listbox.delete(0, tk.END)
        self.blocked_ips.clear()
        self.log_msg("🔓 ALL IPS UNBLOCKED")

if __name__ == "__main__":
    root = tk.Tk()
    app = IPBlocker(root)
    root.mainloop()