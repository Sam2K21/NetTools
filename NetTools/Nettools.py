import subprocess
import os
import platform
import requests
import socket
import re
import ipaddress
from colorama import Fore, init
init(autoreset=True)


def display_banner():
    print(Fore.CYAN + "\n"+
          "--------------------------------------------------------------------------------------------------------------------\n\n"+
          " /##   /##                         /##             /##                                           /##                \n"+
      "| ### | ##                        | ##            | ##                                          | ##                \n"+
      "| ####| ##        /######        /######         /######          /######         /######       | ##        /#######\n"+
      "| ## ## ##       /##__  ##      |_  ##_/        |_  ##_/         /##__  ##       /##__  ##      | ##       /##_____/\n"+
      "| ##  ####      | ########        | ##            | ##          | ##  \ ##      | ##  \ ##      | ##      |  ###### \n"+
      "| ##\  ###      | ##_____/        | ## /##        | ## /##      | ##  | ##      | ##  | ##      | ##       \____  ##\n"+
      "| ## \  ##      |  #######        |  ####/        |  ####/      |  ######/      |  ######/      | ##       /#######/\n"+
      "|__/  \__/       \_______/         \___/           \___/         \______/        \______/       |__/      |_______/ \n\n"+
      "-------------------------------------------------Made by Sam Wright--------------------------------------------------\n")

def clear_screen():
    print("\n" * 100)
    display_banner()

def get_connected_wifi_ssid():
    command = ["netsh", "wlan", "show", "interfaces"]
    result = subprocess.run(command, capture_output=True, text=True).stdout
    for line in result.split("\n"):
        if "SSID" in line:
            return line.split(":")[1].strip()
    return None

def get_connected_wifi_password():
    ssid = get_connected_wifi_ssid()
    if not ssid:
        return None
    command = ["netsh", "wlan", "show", "profile", f"name=\"{ssid}\"", "key=clear"]
    result = subprocess.run(command, capture_output=True, text=True).stdout
    for line in result.split("\n"):
        if "Key Content" in line:
            return line.split(":")[1].strip()
    return None

def get_connected_wifi_authentication():
    ssid = get_connected_wifi_ssid()
    if not ssid:
        return None
    command = ["netsh", "wlan", "show", "profile", f"name=\"{ssid}\""]
    result = subprocess.run(command, capture_output=True, text=True).stdout
    for line in result.split("\n"):
        if "Authentication" in line:
            return line.split(":")[1].strip()
    return None

# New functions for the menu system
def show_menu():
    print("\n----------------\n| MENU OPTIONS |\n----------------")
    print("1. WiFi Information")
    print("2. Device Information")
    print("3. Port Scanner")
    print("4. Exit")
    choice = input("Enter your choice: ")
    return choice


def wifi_information():
    print("--------------------\n| WiFi Information |\n--------------------")

    # Public IP
    try:
        public_ip = requests.get('https://httpbin.org/ip').json()['origin']
        print("Public IP:", public_ip)
    except:
        print("Public IP: Unable to retrieve")

    # Local details from ipconfig
    ipconfig_output = subprocess.check_output("ipconfig", universal_newlines=True).split("\n")
    current_interface = None
    for line in ipconfig_output:
        if "adapter" in line:
            current_interface = line.strip().replace("adapter", "").strip(":")
        if "IPv4 Address" in line:
            print("\nNetwork Interface:", current_interface)
            print("Device IP:", line.split(":")[1].strip())
        if "Subnet Mask" in line:
            print("Subnet Mask:", line.split(":")[1].strip())
        if "Default Gateway" in line:
            gateway = line.split(":")[1].strip()
            if gateway:  # Check if the gateway string is not empty
                print("Gateway:", gateway)
        if "DNS Servers" in line:
            dns = line.split(":")[1].strip()
            if dns:  # Check if the DNS string is not empty
                print("DNS Server:", dns)

    print("\nSSID:", get_connected_wifi_ssid())
    print("Password:", get_connected_wifi_password())
    print("Authentication:", get_connected_wifi_authentication())
    print()  # Print a newline for better formatting


def device_information():
    print("\n----------------------\n| Device Information |\n----------------------")
    # Using platform module
    print("Machine:", platform.machine())
    print("Version:", platform.version())
    print("Platform:", platform.platform())
    print("System:", platform.system())
    print("Processor:", platform.processor())
    # Using os module
    print("Current Directory:", os.getcwd())
    print("Computer Name:", os.environ['COMPUTERNAME'])
    print("Username:", os.environ['USERNAME'])
    # Using subprocess to get system information
    systeminfo_output = subprocess.check_output("systeminfo", universal_newlines=True, timeout=10).split("\n")
    for line in systeminfo_output:
        if "Domain" in line:
            print("Domain:", line.split(":")[1].strip())
        if "OS Name" in line:
            print("OS Name:", line.split(":")[1].strip())
        if "OS Version" in line:
            print("OS Detailed Version:", line.split(":")[1].strip())
        if "System Manufacturer" in line:
            print("System Manufacturer:", line.split(":")[1].strip())
        if "System Model" in line:
            print("System Model:", line.split(":")[1].strip())
        if "System Type" in line:
            print("System Type:", line.split(":")[1].strip())
        if "Total Physical Memory" in line:
            print("Total Physical Memory:", line.split(":")[1].strip())
    print()  # Print a newline for better formatting
    

def port_scanner():
    port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
    port_min = 0
    port_max = 65535
    open_ports = []
# Ask user to input the ip address they want to scan.
    while True:
        ip_add_entered = input("\nPlease enter the ip address that you want to scan: ")
    # If we enter an invalid ip address the try except block will go to the except block and say you entered an invalid ip address.
        try:
            ip_address_obj = ipaddress.ip_address(ip_add_entered)
        # The following line will only execute if the ip is valid.
            print("You entered a valid ip address.")
            break
        except:
            print("You entered an invalid ip address")
    

    while True:
    # You can scan 0-65535 ports. This scanner is basic and doesn't use multithreading so scanning all
    # the ports is not advised.
        print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
        port_range = input("Enter port range: ")
        print("Scanning...")
    # We pass the port numbers in by removing extra spaces that people sometimes enter. 
    # So if you enter 80 - 90 instead of 80-90 the program will still work.
        port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
        if port_range_valid:
        # We're extracting the low end of the port scanner range the user want to scan.
            port_min = int(port_range_valid.group(1))
        # We're extracting the upper end of the port scanner range the user want to scan.
            port_max = int(port_range_valid.group(2))
            break

# Basic socket port scanning
    for port in range(port_min, port_max + 1):
    # Connect to socket of target machine. We need the ip address and the port number we want to connect to.
        try:
        # Create a socket object
        # You can create a socket connection similar to opening a file in Python. 
        # We can change the code to allow for domain names as well.
        # With socket.AF_INET you can enter either a domain name or an ip address 
        # and it will then continue with the connection.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # You want to set a timeout for the socket to try and connect to the server. 
            # If you make the duration longer it will return better results. 
            # We put it at 0.5s. So for every port it scans it will allow 0.5s 
            # for a successful connection.
                s.settimeout(0.5)
            # We use the socket object we created to connect to the ip address we entered and the port number. 
            # If it can't connect to this socket it will cause an exception and the open_ports list will not 
            # append the value.
                s.connect((ip_add_entered, port))
            # If the following line runs then then it was successful in connecting to the port.
                open_ports.append(port)

        except:
        # We don't need to do anything here. If we were interested in the closed ports we'd put something here.
           print(Fore.GREEN + f"Port {port} is not open on {ip_add_entered}.")

# We only care about the open ports.
    for port in open_ports:
    # We use an f string to easily format the string with variables so we don't have to do concatenation.
        print(Fore.RED + f"Port {port} is open on {ip_add_entered}.")

    

def main():
    display_banner()
    while True:
        choice = show_menu()
        clear_screen()
        if choice == "1":
            wifi_information()
        elif choice == "2":
            device_information()
        elif choice == "3":
            port_scanner()
        elif choice == "4":
            print("\nThank you for using Nettools. Goodbye!")
            break
        else:
            print("\nInvalid choice. Please select a valid option.")

# Start the menu-driven system
if __name__ == "__main__":
    main()