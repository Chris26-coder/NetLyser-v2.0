"""
NetLyser - main monitoring and mitigation module (rebranded from NetDeflect)

This is the canonical module name. Keep this file executable as the primary
entrypoint for the project. It contains network monitoring, attack analysis,
and mitigation helpers.
"""

# Terminal color definitions
class TerminalColor:
    BLACK   = '\033[30m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    DARK_GRAY     = '\033[90m'
    PURPLE = '\033[35m'
    RESET  = '\033[0m'

# Version information class
class ApplicationVersion:
    version = "NetLyser v2.0"

import os
import sys
import subprocess
from subprocess import DEVNULL, STDOUT
import json
import configparser
import re
from datetime import datetime
import requests
import psutil
import time
import socket
import threading
import ipaddress
import platform
import logging
from logging.handlers import RotatingFileHandler

# Set recursion limit to handle large data processing
sys.setrecursionlimit(100000000)


# Logging setup (safe, non-throwing)
def setup_logging(log_path='application_data/netlyser.log', level=logging.INFO):
    try:
        # ensure directory exists
        log_dir = os.path.dirname(log_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        logger = logging.getLogger('netlyser')
        logger.setLevel(level)
        # Avoid adding duplicate handlers if setup_logging called multiple times
        if not logger.handlers:
            fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

            # Rotating file handler
            fh = RotatingFileHandler(log_path, maxBytes=1024*1024, backupCount=3, encoding='utf-8')
            fh.setLevel(level)
            fh.setFormatter(fmt)
            logger.addHandler(fh)

            # Console handler
            ch = logging.StreamHandler()
            ch.setLevel(level)
            ch.setFormatter(fmt)
            logger.addHandler(ch)

            # Avoid double logging
            logger.propagate = False

        return logger
    except Exception:
        # If logging setup fails, return a no-op logger
        return logging.getLogger('netlyser')


# Initialize module-level logger
logger = setup_logging()

# Format current timestamp
def get_timestamp():
  now = datetime.now()
  timestamp = now.strftime("%d-%m-%y-%H:%M:%S")
  return timestamp

# Format current timestamp
def get_timeonly():
  now = datetime.now()
  timestamp = now.strftime("%H:%M:%S")
  return timestamp

# Generate console output prefix
def get_output_prefix():
  return f"{TerminalColor.WHITE}[{TerminalColor.RED}{ApplicationVersion.version}{TerminalColor.WHITE}][{TerminalColor.PURPLE}{get_timeonly()}{TerminalColor.WHITE}]{TerminalColor.RESET}"

# Global variables
blocked_ips = []
attack_status = "None"

# Default (safe) configuration values. These will be overwritten by
# `load_config()` when the application is started via `run()`.
ip_method = "opendns"
firewall_system = "blackhole"
webhook_url = ""
detection_threshold = 270
pps_threshold = 15000
trigger_mode = "MP"
mitigation_pause = 55
mbps_threshold = 30
packet_count = 5000
network_interface = "eth0"
filter_arguments = ""
trusted_ips = ["8.8.8.8", "8.8.4.4"]

# Advanced mitigation defaults
enable_fallback_blocking = False
block_other_attack_contributors = False
enable_pattern_detection = True
block_autodetected_patterns = False
contributor_threshold = 30
max_pcap_files = 10

# External API defaults
enable_api_integration = False
api_endpoint = ""
auth_method = "none"
auth_token = ""
auth_username = ""
auth_password = ""
additional_headers = "{}"
request_method = "POST"
request_body_template = ""
request_timeout = 10
sending_mode = "batch"
max_ips_per_batch = 10

# system_ip will be populated by load_config() at runtime
system_ip = "0.0.0.0"


def load_config(settings_path='settings.ini'):
    """Load configuration from file and update module-level settings.

    This function is safe to call at runtime and will not exit the process on
    failure — it falls back to sensible defaults.
    """
    global ip_method, firewall_system, webhook_url, detection_threshold
    global pps_threshold, trigger_mode, mitigation_pause, mbps_threshold
    global packet_count, network_interface, filter_arguments, trusted_ips
    global enable_fallback_blocking, block_other_attack_contributors
    global enable_pattern_detection, block_autodetected_patterns
    global contributor_threshold, max_pcap_files
    global enable_api_integration, api_endpoint, auth_method, auth_token
    global auth_username, auth_password, additional_headers, request_method
    global request_body_template, request_timeout, sending_mode, max_ips_per_batch

    try:
        config = configparser.ConfigParser()
        read_files = config.read(settings_path, encoding='utf-8')

        if 'ip_detection' in config:
            ip_method = config.get('ip_detection', 'ip_method', fallback=ip_method)

        if 'firewall' in config:
            firewall_system = config.get('firewall', 'firewall_system', fallback=firewall_system)

        if 'notification' in config:
            webhook_url = config.get('notification', 'webhook_url', fallback=webhook_url)

        if 'triggers' in config:
            detection_threshold = config.getint('triggers', 'detection_threshold', fallback=detection_threshold)
            pps_threshold = config.getint('triggers', 'pps_threshold', fallback=pps_threshold)
            trigger_mode = config.get('triggers', 'trigger_mode', fallback=trigger_mode)
            mitigation_pause = config.getint('triggers', 'mitigation_pause', fallback=mitigation_pause)
            mbps_threshold = config.getint('triggers', 'mbps_threshold', fallback=mbps_threshold)
            packet_count = config.getint('triggers', 'packet_count', fallback=packet_count)

        if 'capture' in config:
            network_interface = config.get('capture', 'network_interface', fallback=network_interface)
            filter_arguments = config.get('capture', 'filter_arguments', fallback=filter_arguments)

        if 'whitelist' in config:
            trusted = config.get('whitelist', 'trusted_ips', fallback=", ".join(trusted_ips))
            trusted_ips[:] = [ip.strip() for ip in trusted.split(',') if ip.strip()]

        if 'advanced_mitigation' in config:
            enable_fallback_blocking = config.getboolean('advanced_mitigation', 'enable_fallback_blocking', fallback=enable_fallback_blocking)
            block_other_attack_contributors = config.getboolean('advanced_mitigation', 'block_other_attack_contributors', fallback=block_other_attack_contributors)
            enable_pattern_detection = config.getboolean('advanced_mitigation', 'enable_pattern_detection', fallback=enable_pattern_detection)
            block_autodetected_patterns = config.getboolean('advanced_mitigation', 'block_autodetected_patterns', fallback=block_autodetected_patterns)
            contributor_threshold = int(config.get('advanced_mitigation', 'contributor_threshold', fallback=str(contributor_threshold)))
            max_pcap_files = int(config.get('advanced_mitigation', 'max_pcap_files', fallback=str(max_pcap_files)))

        if 'external_firewall' in config:
            enable_api_integration = config.getboolean('external_firewall', 'enable_api_integration', fallback=enable_api_integration)
            api_endpoint = config.get('external_firewall', 'api_endpoint', fallback=api_endpoint)
            auth_method = config.get('external_firewall', 'auth_method', fallback=auth_method)
            auth_token = config.get('external_firewall', 'auth_token', fallback=auth_token)
            auth_username = config.get('external_firewall', 'auth_username', fallback=auth_username)
            auth_password = config.get('external_firewall', 'auth_password', fallback=auth_password)
            additional_headers = config.get('external_firewall', 'additional_headers', fallback=additional_headers)
            request_method = config.get('external_firewall', 'request_method', fallback=request_method)
            request_body_template = config.get('external_firewall', 'request_body_template', fallback=request_body_template)
            request_timeout = int(config.get('external_firewall', 'request_timeout', fallback=str(request_timeout)))
            sending_mode = config.get('external_firewall', 'sending_mode', fallback=sending_mode)
            max_ips_per_batch = int(config.get('external_firewall', 'max_ips_per_batch', fallback=str(max_ips_per_batch)))

    except Exception:
        # On failure, keep defaults and continue. Avoid exiting on import.
        pass

def get_ip(method):
    """
    Robust IP detection with validation and fallbacks.
    Attempts the requested method first, but if the result is not a valid IP
    it falls back to public HTTP services and finally local resolution.
    """
    def is_valid_ip(addr):
        try:
            if not addr:
                return False
            addr = addr.strip()
            ipaddress.ip_address(addr)
            return True
        except Exception:
            return False

    result = ""
    try:
        if method == "google_dns":
            result = subprocess.getoutput('dig TXT +short o-o.myaddr.l.google.com @ns1.google.com').replace('"', '').strip()
        elif method == "opendns":
            result = subprocess.getoutput('dig +short myip.opendns.com @resolver1.opendns.com').strip()
        elif method == "ipify":
            result = requests.get("https://api.ipify.org", timeout=5).text.strip()
        elif method == "icanhazip":
            result = requests.get("https://icanhazip.com", timeout=5).text.strip()
        elif method == "local":
            result = socket.gethostbyname(socket.gethostname())
        else:
            raise ValueError(f"Unknown IP detection method: {method}")
    except Exception:
        result = ""

    if is_valid_ip(result):
        return result.strip()

    # Fallbacks: try common HTTP services then local
    fallbacks = [
        lambda: requests.get("https://api.ipify.org", timeout=5).text.strip(),
        lambda: requests.get("https://icanhazip.com", timeout=5).text.strip(),
        lambda: socket.gethostbyname(socket.gethostname())
    ]

    for fn in fallbacks:
        try:
            candidate = fn()
            if is_valid_ip(candidate):
                return candidate.strip()
        except Exception:
            continue

    raise ValueError(f"Unable to detect system IP using method={method}")
    
system_ip = get_ip(ip_method)

# Create required directory structure
def dir():
    # Define application directories
    directories = [
        "./application_data",
        "./application_data/captures",
        "./application_data/ips",
        "./application_data/attack_analysis"
    ]
    
    # Create each directory if it doesn't exist
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception:
            pass

# Configure ipset tables for IP filtering
def configure_ipset():
    # On Windows, ipset/iptables are not available — treat as no-op
    if platform.system().lower().startswith('win'):
        logger.info(f"{get_output_prefix()} Running on Windows — skipping ipset/iptables configuration (no-op)")
        return

    # Create IP filtering tables
    subprocess.call('ipset -N blocked_ips hash:net family inet', shell=True, stdout=DEVNULL, stderr=STDOUT)
    subprocess.call('ipset -N trusted_ips hash:net family inet', shell=True, stdout=DEVNULL, stderr=STDOUT)

    # Configure iptables rules
    subprocess.call('iptables -t raw -I PREROUTING -m set --match-set blocked_ips src -j DROP', shell=True, stdout=DEVNULL, stderr=STDOUT)
    subprocess.call('iptables -t raw -I PREROUTING -m set --match-set trusted_ips src -j ACCEPT', shell=True, stdout=DEVNULL, stderr=STDOUT)

def is_protected_ip(ip_address):
  # Check if IP is already in blocked list
  if ip_address in blocked_ips:
    return True

  # Protect system's own IP
  if ip_address == system_ip:
    return True

  # Check against trusted IPs list
  if ip_address in trusted_ips:
    return True

  # IP is not protected
  return False

# Format IP address display
def format_ip_display(ip_address):
  length = len(ip_address)
  if 6 <= length <= 15:
      spaces = " " * (15 - length)
      return f"{ip_address}{spaces}"
  return ip_address

def block_ip(ip_address):
  try:
    # Clean up IP string
    ip_address = ip_address.strip()

    # Format for display
    formatted_ip = format_ip_display(ip_address)

    # Skip protected IPs
    if is_protected_ip(ip_address):
      return False

    # Select appropriate firewall command
    cmd = ""
    if firewall_system == 'ufw':
        cmd = f"sudo ufw deny from {ip_address}"
    elif firewall_system == 'ipset':
        cmd = f"ipset -A blocked_ips {ip_address}"
    elif firewall_system == "iptables":
        cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
    elif firewall_system == "blackhole":
        cmd = f"ip route add blackhole {ip_address}"
    else:
        logger.error(f"{get_output_prefix()} Unrecognized firewall_system! Please select \"ufw\", \"iptables\", \"ipset\", or \"blackhole\"")
        exit()
    
    # Execute firewall command; on Windows do a safe no-op block (log only)
    if cmd:
        entry = {
            "ip": ip_address,
            "timestamp": get_timestamp(),
            "action": firewall_system,
            "blocked": True
        }
        # Execute firewall command; on Windows do a safe no-op block (log only)
        if platform.system().lower().startswith('win'):
            # Do not execute system blocking commands on Windows; just log and record
            logger.info(f"{get_output_prefix()} (Windows) Would block malicious IP: {TerminalColor.BLUE}[{TerminalColor.RED}{formatted_ip}{TerminalColor.BLUE}]{TerminalColor.RESET}")
        else:
            subprocess.call(cmd, shell=True, stdout=DEVNULL, stderr=STDOUT)
            logger.info(f"{get_output_prefix()} Blocked malicious IP: {TerminalColor.BLUE}[{TerminalColor.RED}{formatted_ip}{TerminalColor.BLUE}]{TerminalColor.RESET}")

        # Record blocked IP entry (append to file, keep last 100)
        try:
            os.makedirs('./application_data', exist_ok=True)
            blocked_file = './application_data/blocked.json'
            existing = []
            if os.path.exists(blocked_file):
                try:
                    with open(blocked_file, 'r', encoding='utf-8') as bf:
                        existing = json.load(bf)
                except Exception:
                    existing = []
            existing.append(entry)
            # keep only last 100 entries
            existing = existing[-100:]
            with open(blocked_file, 'w', encoding='utf-8') as bf:
                json.dump(existing, bf, indent=2)
        except Exception:
            pass

        # maintain simple in-memory list for backward-compat
        try:
            blocked_ips.append(ip_address)
        except Exception:
            pass

        return True

  except Exception as e:
    logger.error(f"{get_output_prefix()} Error occurred: {TerminalColor.BLUE}[{TerminalColor.RED}{e}{TerminalColor.BLUE}]{TerminalColor.RESET}")
  
  return False

update_available = False
latest_version_tag = ""

def check_for_updates():
    global update_available, latest_version_tag
    try:
        # GitHub API URL for latest release
        api_url = "https://api.github.com/repos/0vm/NetLyser/releases/latest"
        
        # Get current version number (extract from version string)
        current_version = ApplicationVersion.version.split("v")[1].strip() if "v" in ApplicationVersion.version else "2.0"
        
        # Request latest release info
        response = requests.get(api_url, timeout=5)
        if response.status_code != 200:
            return
        
        # Parse response
        release_data = json.loads(response.text)
        latest_version_tag = release_data.get('tag_name', '')
        
        # Extract version number from tag (removing 'v' if present)
        latest_version = latest_version_tag.replace('v', '').strip()
        
        # Simple version comparison (this may not work for complex version schemes)
        if latest_version > current_version:
            # Mark update as available
            update_available = True
    except Exception as e:
        # Silently fail - don't disrupt main application
        pass

def manage_pcap_files(max_files=10):
    """
    Manage the number of pcap files by keeping only the most recent ones
    
    Args:
        max_files (int): Maximum number of pcap files to keep
        
    Returns:
        int: Number of files deleted
    """
    try:
        # Get the pcap directory
        pcap_dir = "./application_data/captures/"
        
        # Get all pcap files in the directory
        pcap_files = []
        for file in os.listdir(pcap_dir):
            if file.endswith(".pcap"):
                file_path = os.path.join(pcap_dir, file)
                # Get file modification time
                mod_time = os.path.getmtime(file_path)
                pcap_files.append((file_path, mod_time))
        
        # If we have more files than the maximum, delete the oldest ones
        if len(pcap_files) > max_files:
            # Sort files by modification time (oldest first)
            pcap_files.sort(key=lambda x: x[1])
            
            # Calculate how many files to delete
            files_to_delete = len(pcap_files) - max_files
            
            # Delete the oldest files
            deleted_count = 0
            for i in range(files_to_delete):
                file_path = pcap_files[i][0]
                try:
                    os.remove(file_path)
                    logger.info(f"{get_output_prefix()} {TerminalColor.BLUE}Deleted old pcap file: {file_path}{TerminalColor.RESET}")
                    deleted_count += 1
                except Exception as e:
                    logger.error(f"{get_output_prefix()} {TerminalColor.RED}Error deleting pcap file {file_path}: {str(e)}{TerminalColor.RESET}")
            
            return deleted_count
        
        return 0
        
    except Exception as e:
        logger.error(f"{get_output_prefix()} {TerminalColor.RED}Error managing pcap files: {str(e)}{TerminalColor.RESET}")
        return 0

def start_update_checker():
    def update_check_worker():
        # Initial delay to let application start properly
        time.sleep(5)
        
        # Do initial check
        check_for_updates()
        
        # Check periodically (every 12 hours)
        while True:
            time.sleep(43200)  # 12 hours
            check_for_updates()
    
    # Start update checker in background thread
    update_thread = threading.Thread(target=update_check_worker)
    update_thread.daemon = True  # Thread will exit when main program exits
    update_thread.start()

def display_update_notification():
    global update_available, latest_version_tag
    if update_available:
        logger.info("\n" + "=" * 80)
        logger.info(f"{get_output_prefix()} Update Available!")
        logger.info(f"{get_output_prefix()} Current Version: {ApplicationVersion.version}")
        logger.info(f"{get_output_prefix()} Latest Version: {latest_version_tag}")
        logger.info(f"{get_output_prefix()} Download at: https://github.com/0vm/NetLyser")
        logger.info("=" * 80)
        return True
    return False

class AttackVectors:
    spoofed_ip_attacks = {}
    valid_ip_attacks = {}
    other_attacks = {}
    
    @classmethod
    def load_vectors(cls):
        try:
            methods_file_path = "methods.json"
            with open(methods_file_path, 'r') as file:
                data = json.load(file)
                
                # Get category-specific attacks
                cls.spoofed_ip_attacks = data.get("spoofed_ip_attacks", {})
                cls.valid_ip_attacks = data.get("valid_ip_attacks", {})
                cls.other_attacks = data.get("other_attacks", {})
                
                return True
        except Exception as e:
            logger.error(f"{get_output_prefix()} Failed to load methods: {str(e)}")
            logger.warning(f"{get_output_prefix()} Make sure to have methods.json in the same directory!")
            return False

def send_ips_to_external_api(ip_list):
    """
    Send IP addresses to an external API based on user configuration
    
    Args:
        ip_list (list): List of IP addresses to block
        
    Returns:
        bool: Success status
    """
    # Skip if API integration is disabled
    if not enable_api_integration:
        return True
    
    # Skip if no IPs to block
    if not ip_list:
        return True
        
    try:
        logger.info(f"{get_output_prefix()} Sending IPs to external firewall API...")
        
        # Determine how to send the IPs based on the sending mode
        if sending_mode.lower() == "single":
            # Send each IP individually
            success = True
            for ip in ip_list:
                if not send_single_ip_to_api(ip):
                    success = False
            return success
            
        elif sending_mode.lower() == "batch":
            # Send IPs in batches
            batches = [ip_list[i:i + max_ips_per_batch] for i in range(0, len(ip_list), max_ips_per_batch)]
            success = True
            for batch in batches:
                if not send_ip_batch_to_api(batch):
                    success = False
            return success
            
        elif sending_mode.lower() == "all":
            # Send all IPs in a single request
            return send_ip_batch_to_api(ip_list)
            
        else:
            logger.error(f"{get_output_prefix()} Unknown sending mode: {sending_mode}")
            return False
            
    except Exception as e:
        logger.error(f"{get_output_prefix()} Error sending IPs to external API: {str(e)}")
        return False


def send_single_ip_to_api(ip):
    """
    Send a single IP to the external API
    
    Args:
        ip (str): IP address to block
        
    Returns:
        bool: Success status
    """
    try:
        # Prepare the request
        url = api_endpoint
        method = request_method.upper()
        
        # Create headers
        headers = parse_json_config(additional_headers)
        
        # Add authentication
        auth = None
        if auth_method.lower() == "basic":
            auth = (auth_username, auth_password)
        elif auth_method.lower() == "bearer":
            headers["Authorization"] = f"Bearer {auth_token}"
        elif auth_method.lower() == "header" and auth_token:
            headers["Authorization"] = auth_token
        
        # Prepare the request body with placeholders
        if request_body_template:
            body = request_body_template.replace("{{IP}}", ip)
            body = body.replace("{{TIMESTAMP}}", get_timestamp())
            body = body.replace("{{SOURCE}}", "NetLyser")
            
            # Convert string to JSON if needed
            if body.strip().startswith("{") or body.strip().startswith("["):
                try:
                    body = json.loads(body)
                except json.JSONDecodeError:
                    pass
        else:
            body = {"ip": ip}
        
        # Send the request
        response = send_api_request(url, method, headers, auth, body)
        
        if response and 200 <= response.status_code < 300:
            logger.info(f"{get_output_prefix()} Successfully sent IP {ip} to external API")
            return True
        else:
            status_code = response.status_code if response else "No response"
            response_text = response.text if response else "No response"
            logger.error(f"{get_output_prefix()} Failed to send IP {ip} to external API: {status_code} - {response_text}")
            return False
            
    except Exception as e:
        logger.error(f"{get_output_prefix()} Error sending IP {ip} to external API: {str(e)}")
        return False


def send_ip_batch_to_api(ip_batch):
    """
    Send a batch of IPs to the external API
    
    Args:
        ip_batch (list): List of IP addresses to block
        
    Returns:
        bool: Success status
    """
    try:
        # Prepare the request
        url = api_endpoint
        method = request_method.upper()
        
        # Create headers
        headers = parse_json_config(additional_headers)
        
        # Add authentication
        auth = None
        if auth_method.lower() == "basic":
            auth = (auth_username, auth_password)
        elif auth_method.lower() == "bearer":
            headers["Authorization"] = f"Bearer {auth_token}"
        elif auth_method.lower() == "header" and auth_token:
            headers["Authorization"] = auth_token
        
        # Prepare the request body with placeholders
        if request_body_template:
            # Format IP list as JSON array string for replacement
            ip_list_json = json.dumps(ip_batch)
            # Format IP list as CSV string for replacement
            ip_list_csv = ",".join(ip_batch)
            
            body = request_body_template.replace("{{IP_LIST}}", ip_list_json)
            body = body.replace("{{IP_CSV}}", ip_list_csv)
            body = body.replace("{{TIMESTAMP}}", get_timestamp())
            body = body.replace("{{SOURCE}}", "NetLyser")
            
            # Convert string to JSON if needed
            if body.strip().startswith("{") or body.strip().startswith("["):
                try:
                    body = json.loads(body)
                except json.JSONDecodeError:
                    pass
        else:
            body = {"ips": ip_batch}
        
        # Send the request
        response = send_api_request(url, method, headers, auth, body)
        
        if response and 200 <= response.status_code < 300:
            print(f"{get_output_prefix()} {TerminalColor.GREEN}Successfully sent {len(ip_batch)} IPs to external API{TerminalColor.RESET}")
            return True
        else:
            status_code = response.status_code if response else "No response"
            response_text = response.text if response else "No response"
            print(f"{get_output_prefix()} {TerminalColor.RED}Failed to send IPs to external API: {status_code} - {response_text}{TerminalColor.RESET}")
            return False
            
    except Exception as e:
        print(f"{get_output_prefix()} {TerminalColor.RED}Error sending IPs to external API: {str(e)}{TerminalColor.RESET}")
        return False


def send_api_request(url, method, headers, auth, body):
    """
    Send request to the API with error handling
    
    Args:
        url (str): API endpoint URL
        method (str): HTTP method
        headers (dict): HTTP headers
        auth (tuple or None): Auth tuple for basic auth
        body (dict or str): Request body
        
    Returns:
        Response or None: Response object or None if failed
    """
    try:
        # Get the request function based on the method
        request_func = getattr(requests, method.lower(), requests.post)
        
        # Send the request with appropriate parameters
        kwargs = {
            "headers": headers,
            "timeout": request_timeout
        }
        
        if auth:
            kwargs["auth"] = auth
            
        if method.upper() in ["GET", "DELETE"]:
            # For GET/DELETE, use params instead of JSON
            if isinstance(body, dict):
                kwargs["params"] = body
        else:
            # For POST/PUT/PATCH, use json or data based on content type
            content_type = headers.get("Content-Type", "").lower()
            if "json" in content_type and isinstance(body, (dict, list)):
                kwargs["json"] = body
            else:
                kwargs["data"] = body
        
        # Send the request
        response = request_func(url, **kwargs)
        return response
        
    except Exception as e:
        print(f"{get_output_prefix()} {TerminalColor.RED}API request error: {str(e)}{TerminalColor.RESET}")
        return None


def parse_json_config(json_string):
    """
    Parse a JSON string from config safely
    
    Args:
        json_string (str): JSON string from config
        
    Returns:
        dict: Parsed JSON object or empty dict if invalid
    """
    if not json_string:
        return {}


    def get_geo_info(ip_address, timeout=3):
        """Return a small geo-info dict for the given IP using ip-api.com.

        Returns: {country, regionName, city, lat, lon} or empty dict on failure.
        """
        if not ip_address or ip_address in ("0.0.0.0", "127.0.0.1"):
            return {}

        try:
            url = f"http://ip-api.com/json/{ip_address}?fields=status,country,regionName,city,lat,lon,message"
            resp = requests.get(url, timeout=timeout)
            if resp.status_code != 200:
                return {}
            data = resp.json()
            if data.get('status') != 'success':
                return {}
            return {
                'country': data.get('country'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon')
            }
        except Exception:
            return {}
        
    try:
        return json.loads(json_string)
    except json.JSONDecodeError as e:
        logger.error(f"{get_output_prefix()} Error parsing JSON config: {str(e)}")
        return {}

# Get network statistics
def get_network_stats():
    # Collect initial network stats
    bytes_initial = int(psutil.net_io_counters().bytes_recv)
    packets_initial = int(psutil.net_io_counters().packets_recv)

    # Wait for next sample
    time.sleep(1)

    # Collect updated network stats
    packets_current = int(psutil.net_io_counters().packets_recv)
    bytes_current = int(psutil.net_io_counters().bytes_recv)

    # Calculate network statistics
    pps = packets_current - packets_initial
    # bytes difference per second -> convert to megabytes (MB/s) with decimals
    bytes_diff = bytes_current - bytes_initial
    mbps = round(bytes_diff / 1024.0 / 1024.0, 3)
    cpu_usage = f"{int(round(psutil.cpu_percent()))}%"
    
    return pps, mbps, cpu_usage

# Display current network status
def display_network_stats(pps, mbps, cpu_usage):
    showed_update = display_update_notification()
    print(f"{get_output_prefix()}           IP Address: {TerminalColor.WHITE}[{TerminalColor.RED}{system_ip}{TerminalColor.WHITE}]{TerminalColor.RESET}")
    print(f"{get_output_prefix()}                  CPU: {TerminalColor.WHITE}[{TerminalColor.RED}{cpu_usage}{TerminalColor.WHITE}]{TerminalColor.RESET}")
    print(f"{get_output_prefix()}                 MB/s: {TerminalColor.WHITE}[{TerminalColor.RED}{mbps}{TerminalColor.WHITE}]{TerminalColor.RESET}")
    print(f"{get_output_prefix()}   Packets Per Second: {TerminalColor.WHITE}[{TerminalColor.RED}{pps}{TerminalColor.WHITE}]{TerminalColor.RESET}")
    # Attempt to enrich status with geo information for the system IP
    try:
        # Inline geo lookup using ip-api.com
        if system_ip and system_ip not in ("0.0.0.0", "127.0.0.1"):
            url = f"http://ip-api.com/json/{system_ip}?fields=status,country,regionName,city,lat,lon,message"
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    geo_info = {
                        'country': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon')
                    }
                else:
                    geo_info = {}
            else:
                geo_info = {}
        else:
            geo_info = {}
    except Exception:
        geo_info = {}
    # Write a machine-readable status file for local dashboards
    try:
        status = {
            "timestamp": get_timestamp(),
            "ip": system_ip,
            "cpu": cpu_usage,
            "mbps": mbps,
            "pps": pps,
            "update_available": update_available,
            "version": ApplicationVersion.version
        }
        # include geo information when available
        try:
            status["geo"] = geo_info if isinstance(geo_info, dict) else {}
        except Exception:
            status["geo"] = {}
        # blocked IPs removed from status output

        # latest_report removed from status output
        # Ensure application_data directory exists
        try:
            os.makedirs('./application_data', exist_ok=True)
        except Exception:
            pass

        with open('./application_data/status.json', 'w', encoding='utf-8') as sf:
            json.dump(status, sf, indent=2)
    except Exception:
        # Don't let status write errors interrupt the main loop
        pass
    return showed_update

def extract_common_patterns(capture_file, min_pattern_length=8, min_occurrence=3, top_ips_count=10):
    try:
        logger.info(f"{get_output_prefix()} Analyzing capture for common attack patterns...")
        top_contributors = find_top_traffic_contributors(capture_file, top_count=top_ips_count)
        if not top_contributors:
            logger.info(f"{get_output_prefix()} No significant traffic contributors found")
            return None, [], 0
        top_ips = []
        for ip, count, percent in top_contributors:
            if not is_protected_ip(ip) and percent > 10:
                top_ips.append(ip)
        if not top_ips:
            logger.info(f"{get_output_prefix()} No non-protected traffic contributors found")
            return None, [], 0
        logger.info(f"{get_output_prefix()} Analyzing payloads from {len(top_ips)} source IPs")
        ip_filter = " or ".join([f"ip.src == {ip}" for ip in top_ips])
        cmd = f'sudo tshark -r {capture_file} -Y "({ip_filter}) and data" -T fields -e ip.src -e data'
        process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if process.returncode != 0 or not process.stdout.strip():
            logger.info(f"{get_output_prefix()} No payload data found in capture")
            return None, [], 0
        ip_payload_map = {}
        all_payloads = []
        for line in process.stdout.strip().split('\n'):
            if '\t' in line:
                parts = line.strip().split('\t')
                if len(parts) == 2:
                    ip = parts[0].strip()
                    payload = parts[1].strip()
                    if len(payload) >= min_pattern_length:
                        if ip not in ip_payload_map:
                            ip_payload_map[ip] = []
                        if payload not in ip_payload_map[ip]:
                            ip_payload_map[ip].append(payload)
                        all_payloads.append(payload)
        if not all_payloads:
            logger.info(f"{get_output_prefix()} No valid payloads found for analysis")
            return None, [], 0
        from collections import Counter
        payload_counter = Counter(all_payloads)
        common_patterns = {}
        for payload, count in payload_counter.most_common(20):
            ip_count = sum(1 for ip, payloads in ip_payload_map.items() if payload in payloads)
            if ip_count >= min(3, len(top_ips)) and count >= min_occurrence:
                common_patterns[payload] = (count, ip_count)
        if not common_patterns:
            substrings = extract_common_substrings(all_payloads, min_length=min_pattern_length)
            if substrings:
                most_common = max(substrings.items(), key=lambda x: x[1][0])
                pattern = most_common[0]
                count = most_common[1][0]
                unique_ips = list(set([ip for ip in top_ips if any(pattern in payload for payload in ip_payload_map.get(ip, []))]))
                if len(unique_ips) >= min(3, len(top_ips)) and count >= min_occurrence:
                    logger.info(f"{get_output_prefix()} Found common substring pattern: {pattern} (occurs {count} times across {len(unique_ips)} IPs)")
                    return pattern, unique_ips, count
            logger.info(f"{get_output_prefix()} No common patterns found across multiple source IPs")
            return None, [], 0
        most_common = max(common_patterns.items(), key=lambda x: x[1][0])
        pattern = most_common[0]
        count = most_common[1][0]
        ip_count = most_common[1][1]
        pattern_ips = [ip for ip, payloads in ip_payload_map.items() if pattern in payloads]
        logger.info(f"{get_output_prefix()} Found common pattern: {pattern} (occurs {count} times across {ip_count} IPs)")
        return pattern, pattern_ips, count
    except Exception as e:
        logger.error(f"{get_output_prefix()} Error analyzing for common patterns: {str(e)}")
        return None, [], 0


def extract_common_substrings(payloads, min_length=8):
    if not payloads or len(payloads) < 2:
        return {}
    sample_payloads = payloads[:min(20, len(payloads))]
    potential_substrings = set()
    for payload in sample_payloads:
        length = len(payload)
        for i in range(length - min_length + 1):
            for j in range(i + min_length, min(i + 64, length + 1)):
                substring = payload[i:j]
                if len(substring) >= min_length:
                    potential_substrings.add(substring)
    substring_counts = {}
    for substring in potential_substrings:
        count = sum(1 for payload in payloads if substring in payload)
        if count >= 3:
            substring_counts[substring] = (count, 0)
    return substring_counts


def save_detected_signature(ip_list, hex_pattern, category="valid_ip_attacks", label=None):
    try:
        if not label:
            prefix = hex_pattern[:min(8, len(hex_pattern))]
            label = f"AutoDetect_{prefix}"
        timestamp = get_timestamp()
        new_entry = {
            "timestamp": timestamp,
            "source_ips": ip_list,
            "pattern": hex_pattern,
            "category": category,
            "label": label
        }
        file_path = "./application_data/new_detected_methods.json"
        existing_entries = []
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    existing_entries = json.load(f)
                    if any(entry["pattern"] == hex_pattern for entry in existing_entries):
                        logger.info(f"{get_output_prefix()} Pattern {hex_pattern} already exists in database")
                        return False
        except Exception as e:
            logger.error(f"{get_output_prefix()} Error reading existing patterns: {str(e)}")
            existing_entries = []
        existing_entries.append(new_entry)
        with open(file_path, 'w') as f:
            json.dump(existing_entries, f, indent=2)
        logger.info(f"{get_output_prefix()} New attack signature detected and saved: Pattern={hex_pattern} Label={label} Category={category} SourceIPs={len(ip_list)}")
        return True
    except Exception as e:
        logger.error(f"{get_output_prefix()} Error saving detected signature: {str(e)}")
        return False


def analyze_unclassified_attack(capture_file):
    result = {
        "pattern_found": False,
        "hex_pattern": None,
        "source_ips": [],
        "category": None,
        "label": None
    }
    try:
        hex_pattern, source_ips, count = extract_common_patterns(capture_file)
        if not hex_pattern or not source_ips or count < 3:
            logger.info(f"{get_output_prefix()} No significant common patterns found in unclassified traffic")
            return result
        category = "valid_ip_attacks"
        prefix = hex_pattern[:min(8, len(hex_pattern))]
        label = f"AutoDetect_{prefix}"
        if save_detected_signature(source_ips, hex_pattern, category, label):
            result["pattern_found"] = True
            result["hex_pattern"] = hex_pattern
            result["source_ips"] = source_ips
            result["category"] = category
            result["label"] = label
        return result
    except Exception as e:
        logger.error(f"{get_output_prefix()} Error analyzing unclassified attack: {str(e)}")
        return result


# Clear previous output lines
def clear_lines(count=5):
    global update_available
    if update_available:
        count += 6
    for i in range(count):
        sys.stdout.write('\x1b[1A')
        sys.stdout.write('\x1b[2K')


# Check if attack thresholds are exceeded
def is_under_attack(pps, mbps):
    if trigger_mode == "MP":
        return pps > pps_threshold and mbps > mbps_threshold
    elif trigger_mode == "P":
        return pps > pps_threshold
    elif trigger_mode == "M":
        return mbps > mbps_threshold
    return False


def get_attack_category(signature_name):
    if signature_name in AttackVectors.spoofed_ip_attacks:
        return 'spoofed'
    elif signature_name in AttackVectors.valid_ip_attacks:
        return 'valid'
    elif signature_name in AttackVectors.other_attacks:
        return 'other'
    else:
        return 'other'


def capture_and_analyze_traffic():
    try:
        if platform.system().lower().startswith('win'):
            capture_file = f"./application_data/captures/traffic.{get_timestamp()}.pcap"
            unique_ip_file = f"./application_data/ips/unique.{get_timestamp()}.txt"
            os.makedirs(os.path.dirname(capture_file), exist_ok=True)
            os.makedirs(os.path.dirname(unique_ip_file), exist_ok=True)
            open(capture_file, 'wb').close()
            open(unique_ip_file, 'w').close()
            logger.info(f"{get_output_prefix()} Running on Windows — capture analysis skipped (no tcpdump/tshark).")
            return capture_file, unique_ip_file, "", "unknown", [], set()
        capture_file = f"./application_data/captures/traffic.{get_timestamp()}.pcap"
        unique_ip_file = f"./application_data/ips/unique.{get_timestamp()}.txt"
        attack_data = ""
        target_port = "unknown"
        malicious_ips = []
        try:
            cmd = f'timeout 28 nice -n -20 ionice -c 1 -n 0 tcpdump "{filter_arguments}" -i {network_interface} -n -s0 -B 8096 -c {packet_count} -w {capture_file}'
            process = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        except subprocess.TimeoutExpired:
            logger.info(f"{get_output_prefix()} tcpdump timed out after 30 seconds, continuing with analysis...")
        if not os.path.exists(capture_file) or os.path.getsize(capture_file) == 0:
            logger.info(f"{get_output_prefix()} No traffic captured or file not created")
            return capture_file, unique_ip_file, attack_data, target_port, malicious_ips, set()
        try:
            cmd = f'sudo tshark -r {capture_file} -T fields -E header=y -e ip.proto -e tcp.flags -e udp.srcport -e tcp.srcport -e data'
            process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if process.returncode != 0:
                logger.error(f"{get_output_prefix()} Error running tshark for attack data")
                return capture_file, unique_ip_file, attack_data, target_port, malicious_ips, set()
            attack_data = process.stdout
        except Exception as e:
            logger.error(f"{get_output_prefix()} Error running tshark for attack data: {str(e)}")
            return capture_file, unique_ip_file, attack_data, target_port, malicious_ips, set()
        try:
            cmd = f'sudo tshark -r {capture_file} -T fields -E header=y -e tcp.dstport -e udp.dstport'
            process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if process.returncode == 0:
                target_port_data = process.stdout
                port_lines = target_port_data.strip().split('\n')
                target_port = port_lines[1].strip() if len(port_lines) > 1 else "unknown"
        except Exception:
            target_port = "unknown"
        attack_type, attack_signatures_readable, attack_categories = analyze_attack_type(attack_data)
        logger.info(f"{get_output_prefix()} Detected attack type: {attack_type}")
        logger.info(f"{get_output_prefix()} Attack categories: {', '.join(attack_categories) if attack_categories else 'None'}")
        unclassified_analysis_result = {"pattern_found": False, "source_ips": []}
        if not attack_categories and enable_pattern_detection:
            logger.info(f"{get_output_prefix()} Unclassified attack detected - analyzing for patterns")
            unclassified_analysis_result = analyze_unclassified_attack(capture_file)
            if unclassified_analysis_result["pattern_found"]:
                hex_pattern = unclassified_analysis_result["hex_pattern"]
                label = unclassified_analysis_result["label"]
                category = unclassified_analysis_result["category"]
                attack_categories.add(category)
                attack_type = f"{TerminalColor.BLUE}[{TerminalColor.GREEN}{label} (auto-detected){TerminalColor.BLUE}]{TerminalColor.RESET}"
                attack_signatures_readable = label
                logger.info(f"{get_output_prefix()} Auto-detected attack pattern: {label}")
        if 'spoofed' in attack_categories and len(attack_categories) == 1:
            logger.info(f"{get_output_prefix()} Pure spoofed IP attack detected - no IP blocking will be performed")
        else:
            if 'valid' in attack_categories:
                for signature, pattern in AttackVectors.valid_ip_attacks.items():
                    if signature in attack_type:
                        logger.info(f"{get_output_prefix()} Looking for valid IP attack sources: {signature}")
                        ips = find_attack_source_ips(capture_file, signature, pattern)
                        for ip in ips:
                            if ip not in malicious_ips and not is_protected_ip(ip):
                                logger.info(f"{get_output_prefix()} Found valid IP attack source: {ip}")
                                malicious_ips.append(ip)
            if 'other' in attack_categories and block_other_attack_contributors:
                logger.info(f"{get_output_prefix()} Analyzing top contributors for 'other_attacks' category (user enabled)")
                top_ips = find_top_traffic_contributors(capture_file)
                for ip, count, percent in top_ips:
                    if percent > contributor_threshold and not is_protected_ip(ip):
                        logger.info(f"{get_output_prefix()} High traffic contributor: {ip} ({percent:.1f}% of traffic)")
                        if ip not in malicious_ips:
                            malicious_ips.append(ip)
            if not attack_categories and not unclassified_analysis_result["pattern_found"] and enable_fallback_blocking:
                logger.info(f"{get_output_prefix()} No known patterns detected - using fallback blocking for top contributors")
                top_ips = find_top_traffic_contributors(capture_file)
                for ip, count, percent in top_ips:
                    if percent > contributor_threshold and not is_protected_ip(ip):
                        logger.info(f"{get_output_prefix()} Fallback blocking high contributor: {ip} ({percent:.1f}% of traffic)")
                        if ip not in malicious_ips:
                            malicious_ips.append(ip)
            if unclassified_analysis_result["pattern_found"] and block_autodetected_patterns:
                logger.info(f"{get_output_prefix()} Adding IPs from auto-detected pattern to block list")
                for ip in unclassified_analysis_result.get("source_ips", []):
                    if ip not in malicious_ips and not is_protected_ip(ip):
                        logger.info(f"{get_output_prefix()} Auto-detected pattern source: {ip}")
                        malicious_ips.append(ip)
            elif unclassified_analysis_result["pattern_found"] and not block_autodetected_patterns:
                logger.info(f"{get_output_prefix()} Auto-detected pattern IPs will be logged but not blocked (user disabled)")
        try:
            with open(unique_ip_file, 'w') as f:
                for ip in malicious_ips:
                    f.write(f"{ip}\n")
        except Exception as e:
            logger.error(f"{get_output_prefix()} Error saving IP list: {str(e)}")
        return capture_file, unique_ip_file, attack_data, target_port, malicious_ips, attack_categories
    except Exception as e:
        logger.error(f"{get_output_prefix()} Error in traffic capture: {str(e)}")
        empty_file = f"./application_data/ips/empty.{get_timestamp()}.txt"
        try:
            open(empty_file, 'w').close()
        except:
            pass
        return "", empty_file, "", "unknown", [], set()


def find_attack_source_ips(capture_file, signature_name, pattern):
    matched_ips = []
    try:
        if pattern.startswith("0x"):
            cmd = f'sudo tshark -r {capture_file} -Y "tcp.flags == {pattern}" -T fields -e ip.src | sort | uniq'
        elif "," in pattern:
            proto_nums = pattern.split(",")[0].strip()
            cmd = f'sudo tshark -r {capture_file} -Y "ip.proto == {proto_nums}" -T fields -e ip.src | sort | uniq'
        elif "\t\t" in pattern:
            parts = pattern.split("\t\t")
            proto_num = parts[0].strip()
            port = parts[1].strip() if len(parts) > 1 else ""
            if port:
                cmd = f'sudo tshark -r {capture_file} -Y "ip.proto == {proto_num} and (tcp.port == {port} or udp.port == {port})" -T fields -e ip.src | sort | uniq'
            else:
                cmd = f'sudo tshark -r {capture_file} -Y "ip.proto == {proto_num}" -T fields -e ip.src | sort | uniq'
        else:
            cmd = f'sudo tshark -r {capture_file} -T fields -e ip.src -e data | grep -i {pattern} | cut -f1 | sort | uniq'
        process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if process.returncode == 0 and process.stdout.strip():
            for ip in process.stdout.strip().split('\n'):
                if ip.strip() and re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip.strip()):
                    matched_ips.append(ip.strip())
    except Exception as e:
        print(f"{get_output_prefix()} Error matching IPs for {signature_name}: {str(e)}")
    return matched_ips


def find_top_traffic_contributors(capture_file, top_count=5, min_percentage=30):
    try:
        cmd = f'sudo tshark -r {capture_file} -T fields -e ip.src | sort | uniq -c | sort -nr | head -{top_count}'
        process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        top_ips = []
        if process.returncode == 0 and process.stdout.strip():
            for line in process.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        try:
                            count = int(parts[0])
                            ip = parts[1]
                            percent = (count * 100) / packet_count
                            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
                                top_ips.append((ip, count, percent))
                        except (ValueError, IndexError):
                            continue
        return top_ips
    except Exception as e:
        print(f"{get_output_prefix()} Error finding top traffic contributors: {str(e)}")
        return []


def analyze_attack_type(packet_data):
    attack_categories = set()
    attack_signatures = []
    cleaned_data = []
    for line in packet_data.split('\n'):
        if not line.startswith('Running') and line.strip():
            cleaned_data.append(line)
    packet_data = '\n'.join(cleaned_data)
    print(f"{get_output_prefix()} Debug: Analyzing {len(packet_data)} bytes of packet data")
    for signature, pattern in AttackVectors.spoofed_ip_attacks.items():
        try:
            match_count = packet_data.count(pattern)
            if match_count > 0:
                print(f"{get_output_prefix()} Debug: Found {match_count} matches for spoofed attack: {signature}")
            if match_count > detection_threshold:
                percentage = min(100.0, (100.0 * float(match_count) / float(packet_count)))
                attack_signatures.append((signature, 'spoofed', percentage))
                attack_categories.add('spoofed')
        except Exception as e:
            print(f"{get_output_prefix()} Error analyzing spoofed signature {signature}: {str(e)}")
    for signature, pattern in AttackVectors.valid_ip_attacks.items():
        try:
            match_count = packet_data.count(pattern)
            if match_count > 0:
                print(f"{get_output_prefix()} Debug: Found {match_count} matches for valid IP attack: {signature}")
            if match_count > detection_threshold:
                percentage = min(100.0, (100.0 * float(match_count) / float(packet_count)))
                attack_signatures.append((signature, 'valid', percentage))
                attack_categories.add('valid')
        except Exception as e:
            print(f"{get_output_prefix()} Error analyzing valid IP signature {signature}: {str(e)}")
    for signature, pattern in AttackVectors.other_attacks.items():
        try:
            match_count = packet_data.count(pattern)
            if match_count > 0:
                print(f"{get_output_prefix()} Debug: Found {match_count} matches for other attack: {signature}")
            if match_count > detection_threshold:
                percentage = min(100.0, (100.0 * float(match_count) / float(packet_count)))
                attack_signatures.append((signature, 'other', percentage))
                attack_categories.add('other')
        except Exception as e:
            print(f"{get_output_prefix()} Error analyzing other signature {signature}: {str(e)}")
    if attack_signatures:
        attack_type = " ".join([f"{signature} ({category}, {percentage:.2f}%)]" for signature, category, percentage in attack_signatures])
        attack_signatures_readable = ", ".join([signature for signature, _, _ in attack_signatures])
    else:
        attack_type = f"{TerminalColor.BLUE}[{TerminalColor.RED}Unclassified{TerminalColor.BLUE}]{TerminalColor.RESET}"
        attack_signatures_readable = "[Unclassified]"
    if attack_signatures:
        print(f"{get_output_prefix()} Found attack signatures: {attack_signatures_readable}")
    return attack_type, attack_signatures_readable, attack_categories


def block_malicious_ips(unique_ip_file):
    global blocked_ips
    with open(unique_ip_file) as file:
        ip_list = [line.strip() for line in file.readlines() if line.strip()]
    total_ips = len(ip_list)
    blocked_count = 0
    actual_blocked = []
    for ip_address in ip_list:
        if block_ip(ip_address):
            blocked_count += 1
            actual_blocked.append(ip_address)
    return total_ips, blocked_count, actual_blocked


def evaluate_mitigation(pps, mbps):
    if pps < pps_threshold and mbps < mbps_threshold:
        logger.info(f"{get_output_prefix()} Traffic volume: Decreased")
        logger.info(f"{get_output_prefix()} Attack Status: Mitigated")
        return "Decreased (mitigated)"
    elif (pps > pps_threshold and mbps < mbps_threshold) or (pps < pps_threshold and mbps > mbps_threshold):
        logger.info(f"{get_output_prefix()} Traffic volume: Decreased")
        logger.info(f"{get_output_prefix()} Attack Status: Partially Mitigated")
        return "Decreased (partially mitigated)"
    else:
        logger.warning(f"{get_output_prefix()} Traffic volume: Increased")
        logger.warning(f"{get_output_prefix()} Attack Status: Ongoing")
        return "Ongoing Attack"


def send_notification(notification_template, attack_id, pps, mbps, cpu_usage, status, total_ips, attack_signatures_readable, attack_categories, auto_detected=False, pattern_label=None):
    attack_category_str = ', '.join(attack_categories) if attack_categories else "Unknown"
    if 'spoofed' in attack_categories and len(attack_categories) == 1:
        blocking_strategy = "Logging only"
    elif auto_detected and not block_autodetected_patterns:
        blocking_strategy = "Auto-pattern detection (logging only)"
    elif auto_detected and block_autodetected_patterns:
        blocking_strategy = f"Auto-pattern detection and blocking: {pattern_label}"
    elif 'other' in attack_categories and block_other_attack_contributors:
        blocking_strategy = "Other attacks: blocking top contributors"
    else:
        blocking_strategy = "Standard blocking"
    report_path = f"**./application_data/attack_analysis/{get_timestamp()}.txt**"
    notification_json = json.dumps(notification_template)
    notification_json = notification_json.replace("{{attack_id}}", str(attack_id))
    notification_json = notification_json.replace("{{pps}}", str(pps))
    notification_json = notification_json.replace("{{mbps}}", str(mbps * 8))
    notification_json = notification_json.replace("{{cpu}}", str(cpu_usage))
    notification_json = notification_json.replace("{{status}}", str(status))
    notification_json = notification_json.replace("{{block_count}}", str(total_ips))
    notification_json = notification_json.replace("{{report_file}}", str(report_path))
    notification_json = notification_json.replace("{{attack_vector}}", str(attack_signatures_readable))
    notification_json = notification_json.replace("{{attack_category}}", str(attack_category_str))
    notification_json = notification_json.replace("{{blocking_strategy}}", str(blocking_strategy))
    try:
        headers = {'content-type': 'application/json'}
        requests.post(webhook_url, notification_json, headers=headers, timeout=3)
        logger.info(f"{get_output_prefix()} Notification Status: Sent")
        return True
    except Exception:
        logger.error(f"{get_output_prefix()} Notification Status: Failed")
        return False


def main():
    global blocked_ips
    start_update_checker()
    
    # Load notification template
    try:
        with open('notification_template.json', 'r', encoding='utf-8') as webhook:
            notification_template = json.load(webhook)
    except:
        # Default notification template
        default_template = {
        "content": None,
        "embeds": [
            {
                "title": "⚠️ DDoS Attack Mitigated: #{{attack_id}}",
                "description": "NetLyser detected and responded to a potential attack.",
                "url": "https://github.com/0vm/NetLyser",
                "color": 16734296,
                "fields": [
                    {
                        "name": "📊 Pre-Mitigation Stats",
                        "value": (
                            "• **Packets/s (PPS):** {{pps}}\n"
                            "• **Megabits/s (Mbps):** {{mbps}}\n"
                            "• **CPU Usage:** {{cpu}}"
                        ),
                        "inline": False
                    },
                    {
                        "name": "🛡️ Post-Mitigation Results",
                        "value": (
                            "• **Status:** {{status}}\n"
                            "• **IPs Blocked:** {{block_count}}\n"
                            "• **Attack Type:** {{attack_vector}}\n"
                            "• **Attack Category:** {{attack_category}}\n"
                            "• **Blocking Strategy:** {{blocking_strategy}}"
                        ),
                        "inline": False
                    },
                    {
                        "name": "📁 Analysis Report",
                        "value": "{{report_file}}",
                        "inline": True
                    }
                ],
                "author": {
                    "name": "NetLyser",
                    "icon_url": "https://avatars.githubusercontent.com/u/79897291?s=96&v=4"
                },
                "footer": {
                    "text": "github.com/0vm/NetLyser",
                    "icon_url": "https://github.githubassets.com/assets/GitHub-Mark-ea2971cee799.png"
                }
            }
        ]
    }
        
        with open('notification_template.json', 'w', encoding='utf-8') as f:
            json.dump(default_template, f, ensure_ascii=False, indent=4)

        # Inform user
        logger.error(f"{get_output_prefix()} notification_template.json creation failed")
        logger.info(f"{get_output_prefix()} notification_template.json has been reset")
        logger.info(f"{get_output_prefix()} Please update notification_template.json with your custom notification format.")

        # Exit application
        exit()

    # Print external API status
    if enable_api_integration:
        logger.info(f"{get_output_prefix()} External firewall API integration enabled: {api_endpoint}")
        logger.info(f"{get_output_prefix()} Mode: {sending_mode} ({request_method})")
    
    # Main monitoring loop
    while True:
        try:
            # Get current network stats
            pps, mbps, cpu_usage = get_network_stats()
            
            # Display current network status
            display_network_stats(pps, mbps, cpu_usage)

            # Clear previous lines for clean output
            clear_lines()

        except Exception as e:
            logger.error(str(e))
            exit()

        # Check for attack conditions
        if is_under_attack(pps, mbps):
            # Display current network stats again (without clearing)
            display_network_stats(pps, mbps, cpu_usage)
        
            # Alert user of threshold breach
            logger.warning(f"{get_output_prefix()} Limit Exceeded: MITIGATION ACTIVE")
            
            try:
                # Capture and analyze traffic with auto-detection
                capture_file, unique_ip_file, attack_data, target_port, malicious_ips, attack_categories = capture_and_analyze_traffic()
                
                # Make sure we have valid data before proceeding
                if not capture_file or not attack_data:
                    print(f"{get_output_prefix()} Failed to capture traffic data, skipping this detection cycle.")
                    time.sleep(mitigation_pause)
                    continue
                
                # Check if this was an auto-detected pattern
                auto_detected = False
                auto_pattern_label = None
                
                # Re-analyze attack data to get the updated attack type after auto-detection
                attack_type, attack_signatures_readable, _ = analyze_attack_type(attack_data)
                
                # Check if it's an auto-detected pattern
                if "auto-detected" in attack_type:
                    auto_detected = True
                    auto_pattern_label = attack_signatures_readable
                
                # Display attack classification
                print(f"{get_output_prefix()} Detected attack type: {attack_type}")
                
                # Format attack categories for display
                attack_category_str = ', '.join(attack_categories) if attack_categories else "Unknown"
                print(f"{get_output_prefix()} Attack categories: {attack_category_str}")
                
                # Block malicious IPs
                total_ips = len(malicious_ips)
                blocked_count = 0
                actual_blocked = []
                
                for ip_address in malicious_ips:
                    if block_ip(ip_address):
                        blocked_count += 1
                        actual_blocked.append(ip_address)
                
                # If external API integration is enabled, send IPs to the external API
                api_success = False
                if enable_api_integration and actual_blocked:
                    api_success = send_ips_to_external_api(actual_blocked)
                
                # Brief pause for clean output
                time.sleep(1)
                
                # Format the list of IPs for reporting
                detected_ips = ' '.join(malicious_ips)
                
                # Get post-mitigation stats
                pps_after, mbps_after, cpu_after = get_network_stats()
                
                # Display attack classification again
                print(f"{get_output_prefix()} Detected attack type: {attack_type}")
                
                # Evaluate mitigation effectiveness
                attack_status = evaluate_mitigation(pps_after, mbps_after)
                
                # Generate attack ID
                attack_id = len(os.listdir("./application_data/captures"))
                
                # Determine blocking strategy
                if 'spoofed' in attack_categories and len(attack_categories) == 1:
                    block_strategy = "Logging only (No blocking)"
                elif auto_detected and not block_autodetected_patterns:
                    block_strategy = "Auto-detected pattern (Logging only)"
                elif auto_detected and block_autodetected_patterns:
                    block_strategy = f"Auto-detected pattern with blocking: {auto_pattern_label}"
                elif 'other' in attack_categories and block_other_attack_contributors:
                    block_strategy = "Other attacks: blocking top contributors"
                else:
                    block_strategy = "Standard blocking"
                
                # Add external API info if enabled
                if enable_api_integration:
                    api_status = "success" if api_success else "failed"
                    block_strategy += f" + External API ({api_status})"
                
                # Generate analysis report
                analysis_report = f"""-----   Analysis Report: {get_timestamp()}   -----
        Pre-Mitigation:
          • Packets Per Second: {pps}
          • Megabits Per Second: {mbps * 8}
          • CPU Utilization: {cpu_usage}
        
        Post-Mitigation:
          • Packets Per Second: {pps_after}
          • Megabits Per Second: {mbps_after * 8}
          • CPU Utilization: {cpu_after}
        
        Details:
          • IPs Detected: {total_ips}
          • IPs Found: {detected_ips}
          • IPs Blocked: {', '.join(actual_blocked) if actual_blocked else "None"} 
          • Attack Type: {attack_signatures_readable}
          • Attack Category: {attack_category_str}
          • Target Port: {target_port}
          • Target IP: {system_ip}
        
        Status:
          • Mitigation Status: {attack_status}
          • Block Strategy: {block_strategy}"""
                
                # Add auto-detection info if applicable
                if auto_detected:
                    analysis_report += f"""
        
        Auto-Detection:
          • Pattern: {auto_pattern_label}
          • Blocking Enabled: {block_autodetected_patterns}
          • Auto-detection entries are stored in: ./application_data/new_detected_methods.json"""
                
                # Add external API info if enabled
                if enable_api_integration:
                    analysis_report += f"""
        
        External API Integration:
          • Endpoint: {api_endpoint}
          • Mode: {sending_mode} ({request_method})
          • Status: {"Success" if api_success else "Failed"}"""
                
                try:
                    # Save analysis report
                    with open(f"./application_data/attack_analysis/{get_timestamp()}.txt", "w") as report_file:
                        report_file.write(analysis_report)
                except Exception as e:
                    logger.error(f"{get_output_prefix()} Failed to save analysis report: {str(e)}")
                
                # Send notification
                send_notification(
                    notification_template, 
                    attack_id, 
                    pps, mbps, cpu_usage, 
                    attack_status, total_ips, 
                    attack_signatures_readable, 
                    attack_categories,
                    auto_detected,
                    auto_pattern_label
                )
                
                # Pause before next scan
                logger.info(f"{get_output_prefix()} Pausing Mitigation for: {mitigation_pause} seconds")
                
                # Clear blocked IPs list for next run
                blocked_ips = []
                
                # Clean up old pcap files if needed
                if max_pcap_files > 0:
                    deleted_files = manage_pcap_files(max_pcap_files)
                    if deleted_files > 0:
                        logger.info(f"{get_output_prefix()} Cleaned up {deleted_files} old pcap files, keeping most recent {max_pcap_files}")


                # Pause before next detection cycle
                time.sleep(mitigation_pause)
                
            except Exception as e:
                logger.error(f"{get_output_prefix()} Error during attack handling: {str(e)}")
                logger.info(f"{get_output_prefix()} Pausing before next detection cycle")
                time.sleep(mitigation_pause),

def run():
    """Start the NetLyser application (safe entrypoint).

    This will perform necessary initialization and then start the main
    monitoring loop. Importing this module will no longer perform these
    side-effects.
    """
    # Ensure directories exist
    dir()

    # Load configuration values from settings.ini (if present)
    load_config()

    # Determine system IP (best-effort; failures fall back to 0.0.0.0)
    global system_ip
    try:
        system_ip = get_ip(ip_method)
    except Exception:
        system_ip = "0.0.0.0"

    # Load attack vectors
    if not AttackVectors.load_vectors():
        return

    # Init ipset if needed
    if firewall_system == 'ipset':
        configure_ipset()

    # Start monitoring loop
    main()


if __name__ == '__main__':
    run()
