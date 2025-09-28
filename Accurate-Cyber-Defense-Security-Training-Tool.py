import socket
import threading
import time
import requests
import json
import subprocess
import os
from datetime import datetime
import scapy.all as scapy
from scapy.all import IP, TCP, UDP, ICMP
import logging
from typing import Dict, List, Set
import sys

class CyberSecurityMonitor:
    def __init__(self):
        self.monitored_ips = set()
        self.is_monitoring = False
        self.monitoring_thread = None
        self.command_history = []
        self.telegram_token = None
        self.telegram_chat_id = None
        self.log_file = "cybersecurity_logs.txt"
        self.threat_logs = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger()
        
        self.setup_interface()

    def setup_interface(self):
        """Setup the green-themed interface"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()

    def print_banner(self):
        """Print the main banner"""
        banner = """
        \033[92m
        ╔══════════════════════════════════════════════════════════════╗
        ║                                                              ║
        ║    🛡️  ACCURATE CYBER SECURITY TRAINING TOOL         L 🛡️   ║
        ║                                                              ║
        ║      Community:https://github.com/Accurate-Cyber-Defense     ║
        ║                                                              ║
        ╚══════════════════════════════════════════════════════════════╝
        \033[0m
        """
        print(banner)

    def print_green(self, text):
        """Print text in green color"""
        print(f"\033[92m{text}\033[0m")

    def print_red(self, text):
        """Print text in red color for warnings"""
        print(f"\033[91m{text}\033[0m")

    def log_command(self, command):
        """Log command to history"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.command_history.append(f"{timestamp} - {command}")

    def send_telegram_message(self, message):
        """Send message via Telegram"""
        if not self.telegram_token or not self.telegram_chat_id:
            self.print_red("Telegram not configured. Use 'config telegram token' and 'config telegram chat_id'")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                "chat_id": self.telegram_chat_id,
                "text": message,
                "parse_mode": "HTML"
            }
            response = requests.post(url, data=data)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Telegram error: {e}")
            return False

    def ping_ip(self, ip):
        """Ping an IP address"""
        try:
            self.print_green(f"Pinging {ip}...")
            result = subprocess.run(['ping', '-c', '4', ip] if os.name != 'nt' else ['ping', '-n', '4', ip],
                                  capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Ping error: {e}"

    def scan_ports(self, ip, start_port=1, end_port=1000, deep_scan=False):
        """Scan ports on an IP address"""
        self.print_green(f"Scanning {ip} from port {start_port} to {end_port}...")
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
                    service = socket.getservbyport(port, 'tcp') if port <= 1000 else "Unknown"
                    self.print_green(f"Port {port} ({service}) is open")
            except:
                pass

        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        
        for t in threads:
            t.join()
            
        return open_ports

    def get_ip_location(self, ip):
        """Get geographical location of IP"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            if data['status'] == 'success':
                return f"""
Country: {data['country']}
Region: {data['regionName']}
City: {data['city']}
ISP: {data['isp']}
Latitude: {data['lat']}
Longitude: {data['lon']}
                """
            return "Location not found"
        except Exception as e:
            return f"Location error: {e}"

    def traceroute(self, ip, protocol='udp'):
        """Perform traceroute"""
        try:
            self.print_green(f"Performing {protocol.upper()} traceroute to {ip}...")
            result = subprocess.run(['traceroute', '-w', '1', ip] if protocol == 'udp' else ['traceroute', '-T', ip],
                                  capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Traceroute error: {e}"

    def monitor_threats(self):
        """Monitor for cybersecurity threats"""
        while self.is_monitoring:
            for ip in list(self.monitored_ips):
                self.check_for_threats(ip)
            time.sleep(10)  # Check every 10 seconds

    def check_for_threats(self, ip):
        """Check for various cyber threats"""
        threats = []
        
        # Check for port scanning activity
        port_scan_result = self.detect_port_scan(ip)
        if port_scan_result:
            threats.append(port_scan_result)
            
        # Check for DOS/DDOS patterns
        dos_result = self.detect_dos_patterns(ip)
        if dos_result:
            threats.append(dos_result)
            
        # Log threats
        for threat in threats:
            log_entry = f"{datetime.now()} - THREAT DETECTED - {ip} - {threat}"
            self.threat_logs.append(log_entry)
            self.logger.warning(log_entry)
            
            # Send Telegram alert
            if self.telegram_token and self.telegram_chat_id:
                self.send_telegram_message(f"🚨 THREAT ALERT 🚨\nIP: {ip}\nThreat: {threat}")

    def detect_port_scan(self, ip):
        """Detect port scanning activity"""
        # Simulate port scan detection logic
        if len(self.threat_logs) > 10:  # Simple heuristic
            return "Possible port scanning detected"
        return None

    def detect_dos_patterns(self, ip):
        """Detect DOS/DDOS patterns"""
        # Simulate DOS detection logic
        return None  # Placeholder for actual implementation

    def view_logs(self):
        """View security logs"""
        try:
            with open(self.log_file, 'r') as f:
                return f.read()
        except:
            return "No logs available"

    def export_data(self):
        """Export data to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_export_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write("ACCURATE DEFENSE SECURITY TOOL EXPORT DATA\n")
            f.write("=" * 50 + "\n")
            f.write(f"Export Time: {datetime.now()}\n\n")
            
            f.write("MONITORED IPS:\n")
            for ip in self.monitored_ips:
                f.write(f"- {ip}\n")
                
            f.write("\nTHREAT LOGS:\n")
            for log in self.threat_logs[-100:]:  # Last 100 entries
                f.write(f"{log}\n")
                
            f.write("\nCOMMAND HISTORY:\n")
            for cmd in self.command_history[-50:]:  # Last 50 commands
                f.write(f"{cmd}\n")
                
        return f"Data exported to {filename}"

    def handle_telegram_command(self, command, args):
        """Handle Telegram bot commands"""
        commands = {
            '/help': self.show_help,
            '/ping_ip': lambda: self.ping_ip(args[0]) if args else "Usage: /ping_ip [IP]",
            '/start_monitoring_ip': lambda: self.start_monitoring_ip(args[0]) if args else "Usage: /start_monitoring_ip [IP]",
            '/stop': self.stop_monitoring,
            '/status': self.show_status,
            '/location_ip': lambda: self.get_ip_location(args[0]) if args else "Usage: /location_ip [IP]",
            '/scan_ip': lambda: f"Open ports: {self.scan_ports(args[0])}" if args else "Usage: /scan_ip [IP]",
            '/deep_scan_ip': lambda: f"Open ports: {self.scan_ports(args[0], 1, 66535, True)}" if args else "Usage: /deep_scan_ip [IP]",
            '/view': lambda: self.view_logs(),
            '/history': lambda: "\n".join(self.command_history[-10:]),
            '/udptraceroute': lambda: self.traceroute(args[0], 'udp') if args else "Usage: /udptraceroute [IP]",
            '/tcptraceroute': lambda: self.traceroute(args[0], 'tcp') if args else "Usage: /tcptraceroute [IP]",
        }
        
        if command in commands:
            return commands[command]()
        return "Unknown command"

    def show_help(self):
        """Show help menu"""
        help_text = """
🛡️ CYBER SECURITY TOOL - COMMAND HELP 🛡️

Basic Commands:
- help: Show this help message
- ping [ip]: Ping an IP address
- scan [ip]: Scan common ports (1-1000)
- deep_scan [ip]: Deep scan all ports (1-66535)
- location [ip]: Get IP geographical location
- udptraceroute [ip]: UDP traceroute
- tcptraceroute [ip]: TCP traceroute

Monitoring Commands:
- start monitoring [ip]: Start monitoring IP for threats
- stop monitoring: Stop all monitoring
- status: Show monitoring status
- view: View security logs
- add [ip]: Add IP to monitoring list
- remove [ip]: Remove IP from monitoring list

Telegram Commands:
- config telegram token [token]: Set Telegram bot token
- config telegram chat_id [id]: Set Telegram chat ID
- export: Export data to file

System Commands:
- history: View command history
- exit: Exit the program

Telegram Bot Commands (prefix with /):
/help, /ping_ip, /start_monitoring_ip, /stop, /status, 
/location_ip, /scan_ip, /deep_scan_ip, /view, /history,
/udptraceroute, /tcptraceroute
        """
        return help_text

    def start_monitoring_ip(self, ip):
        """Start monitoring an IP address"""
        self.monitored_ips.add(ip)
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitoring_thread = threading.Thread(target=self.monitor_threats)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
        return f"Started monitoring {ip}"

    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_monitoring = False
        self.monitored_ips.clear()
        return "Monitoring stopped"

    def show_status(self):
        """Show monitoring status"""
        status = f"""
Monitoring Status: {'ACTIVE 🟢' if self.is_monitoring else 'INACTIVE 🔴'}
Monitored IPs: {len(self.monitored_ips)}
Threats Detected: {len(self.threat_logs)}
Telegram Configured: {'YES' if self.telegram_token and self.telegram_chat_id else 'NO'}

Monitored IP Addresses:
"""
        for ip in self.monitored_ips:
            status += f"- {ip}\n"
        return status

    def run(self):
        """Main program loop"""
        self.print_green("Accurate Cyber Defense Training Tool Started! Type 'help' for commands.")
        
        while True:
            try:
                command = input("\n\033[92mAccurat#>\033[0m ").strip()
                if not command:
                    continue
                    
                self.log_command(command)
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd == 'exit':
                    self.stop_monitoring()
                    self.print_green("Goodbye! Stay secure! 🛡️")
                    break
                    
                elif cmd == 'help':
                    self.print_green(self.show_help())
                    
                elif cmd == 'ping':
                    if args:
                        result = self.ping_ip(args[0])
                        self.print_green(result)
                    else:
                        self.print_red("Usage: ping [IP]")
                        
                elif cmd == 'scan':
                    if args:
                        open_ports = self.scan_ports(args[0])
                        self.print_green(f"Scan completed. Open ports: {open_ports}")
                    else:
                        self.print_red("Usage: scan [IP]")
                        
                elif cmd == 'deep_scan':
                    if args:
                        self.print_green("Starting deep scan (this may take a while)...")
                        open_ports = self.scan_ports(args[0], 1, 66535, True)
                        self.print_green(f"Deep scan completed. Open ports: {open_ports}")
                    else:
                        self.print_red("Usage: deep_scan [IP]")
                        
                elif cmd == 'location':
                    if args:
                        result = self.get_ip_location(args[0])
                        self.print_green(result)
                    else:
                        self.print_red("Usage: location [IP]")
                        
                elif cmd == 'udptraceroute':
                    if args:
                        result = self.traceroute(args[0], 'udp')
                        self.print_green(result)
                    else:
                        self.print_red("Usage: udptraceroute [IP]")
                        
                elif cmd == 'tcptraceroute':
                    if args:
                        result = self.traceroute(args[0], 'tcp')
                        self.print_green(result)
                    else:
                        self.print_red("Usage: tcptraceroute [IP]")
                        
                elif cmd == 'start' and len(args) > 1 and args[0] == 'monitoring':
                    if len(args) > 1:
                        result = self.start_monitoring_ip(args[1])
                        self.print_green(result)
                    else:
                        self.print_red("Usage: start monitoring [IP]")
                        
                elif cmd == 'stop':
                    result = self.stop_monitoring()
                    self.print_green(result)
                    
                elif cmd == 'status':
                    result = self.show_status()
                    self.print_green(result)
                    
                elif cmd == 'view':
                    result = self.view_logs()
                    self.print_green(result)
                    
                elif cmd == 'add':
                    if args:
                        self.monitored_ips.add(args[0])
                        self.print_green(f"Added {args[0]} to monitoring list")
                    else:
                        self.print_red("Usage: add [IP]")
                        
                elif cmd == 'remove':
                    if args:
                        if args[0] in self.monitored_ips:
                            self.monitored_ips.remove(args[0])
                            self.print_green(f"Removed {args[0]} from monitoring list")
                        else:
                            self.print_red("IP not in monitoring list")
                    else:
                        self.print_red("Usage: remove [IP]")
                        
                elif cmd == 'history':
                    self.print_green("Command History:")
                    for i, cmd in enumerate(self.command_history[-10:], 1):
                        self.print_green(f"{i}. {cmd}")
                        
                elif cmd == 'config' and len(args) > 2:
                    if args[0] == 'telegram':
                        if args[1] == 'token':
                            self.telegram_token = args[2]
                            self.print_green("Telegram token configured")
                        elif args[1] == 'chat_id':
                            self.telegram_chat_id = args[2]
                            self.print_green("Telegram chat ID configured")
                        else:
                            self.print_red("Usage: config telegram [token|chat_id] [value]")
                    else:
                        self.print_red("Usage: config telegram [token|chat_id] [value]")
                        
                elif cmd == 'export':
                    result = self.export_data()
                    self.print_green(result)
                    
                else:
                    self.print_red("Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                self.print_green("\nGoodbye! Stay secure! 🛡️")
                break
            except Exception as e:
                self.print_red(f"Error: {e}")

def main():
    """Main function"""
    # Check if running as root for some network operations
    if os.name != 'nt' and os.geteuid() != 0:
        print("\033[91mWarning: Some features may require root privileges\033[0m")
    
    monitor = CyberSecurityMonitor()
    monitor.run()

if __name__ == "__main__":
    main()