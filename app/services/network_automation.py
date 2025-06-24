import subprocess
import os
import json
import logging
import yaml
import ipaddress
import re

# Import Flask-SQLAlchemy db instance and the new models
from app.models import db, Device, Interface, ArpEntry, RouteEntry

app_logger = logging.getLogger(__name__)

# --- ADD THIS LINE FOR DEBUGGING ---
app_logger.debug(f"DEBUG: network_automation.py is being loaded from: {os.path.abspath(__file__)}")

# Define the directory where Ansible output files are stored
OUTPUTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'outputs')

class NetworkAutomationService:
    def __init__(self, inventory_path='inventory.yml', playbook_dir='.'):
        project_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
        self.inventory_path = os.path.join(project_root, inventory_path)
        self.playbook_dir = os.path.join(project_root, playbook_dir)
        
        self.ansible_tmp_dir = os.path.join(project_root, 'ansible_tmp')

        if not os.path.exists(self.inventory_path):
            app_logger.error(f"Inventory file not found at: {self.inventory_path}")
            raise FileNotFoundError(f"Inventory file not found at: {self.inventory_path}")

        os.makedirs(OUTPUTS_DIR, exist_ok=True)
        app_logger.info(f"Ansible outputs directory set to: {OUTPUTS_DIR}")
        
        os.makedirs(self.ansible_tmp_dir, exist_ok=True)
        app_logger.info(f"Ansible temporary directory set to: {self.ansible_tmp_dir}")


    def _execute_ansible_playbook(self, playbook_name, extra_vars=None):
        """
        Internal helper to execute an Ansible playbook.
        Returns stdout and stderr from the playbook execution.
        """
        playbook_path = os.path.join(self.playbook_dir, playbook_name)
        if not os.path.exists(playbook_path):
            app_logger.error(f"Ansible playbook not found: {playbook_path}")
            raise FileNotFoundError(f"Ansible playbook not found: {playbook_path}")

        command = [
            'ansible-playbook',
            playbook_path,
            '-i', self.inventory_path
        ]

        if extra_vars:
            command.extend(['--extra-vars', json.dumps(extra_vars)])

        env = os.environ.copy()
        
        # --- FIX 1: Disable SSH Host Key Checking (for development) ---
        env['ANSIBLE_HOST_KEY_CHECKING'] = 'False'
        
        # --- FIX 2: Correct ANSIBLE_COLLECTIONS_PATHS to ANSIBLE_COLLECTIONS_PATH ---
        env['ANSIBLE_COLLECTIONS_PATH'] = os.path.join(self.playbook_dir, 'ansible_collections') # Corrected name
        # Remove the old incorrect variable if it was there or if you had a separate line for it
        if 'ANSIBLE_COLLECTIONS_PATHS' in env:
            del env['ANSIBLE_COLLECTIONS_PATHS']
        # --- END FIXES ---

        env['ANSIBLE_CACHE_DIR'] = os.path.join(self.ansible_tmp_dir, 'cache')
        env['ANSIBLE_TMPDIR'] = self.ansible_tmp_dir
        env['TMPDIR'] = self.ansible_tmp_dir
        # The HOME and USER variables are often not strictly necessary if other TMPDIR/CACHE_DIR are set correctly
        # and host_key_checking is off, but can be kept if they resolve correctly for the Gunicorn user.
        # For robustness, we might explicitly set them if we know Gunicorn's home.
        # For now, let's keep them commented out as they might have been the source of '/nonexistent' earlier.
        # env['HOME'] = user_home # If you're confident this resolves to a writable path for the gunicorn user
        # env['USER'] = 'firework_app_user'


        app_logger.debug("--- Subprocess Environment for Ansible ---")
        for k, v in env.items():
            if k in ['PATH', 'USER', 'HOME', 'ANSIBLE_CACHE_DIR', 'ANSIBLE_TMPDIR', 'TMPDIR', 'ANSIBLE_COLLECTIONS_PATH', 'ANSIBLE_HOST_KEY_CHECKING']: # Added new var
                app_logger.debug(f"  {k}={v}")
        app_logger.debug("----------------------------------------")

        cwd = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')

        app_logger.info(f"Executing Ansible command: {' '.join(command)} in CWD: {cwd}")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                cwd=cwd,
                env=env
            )
            app_logger.info(f"Ansible playbook '{playbook_name}' executed successfully.")
            return result.stdout, result.stderr
        except subprocess.CalledProcessError as e:
            app_logger.error(f"Ansible playbook '{playbook_name}' failed with exit code {e.returncode}.")
            app_logger.error(f"STDOUT: {e.stdout}")
            app_logger.error(f"STDERR: {e.stderr}")
            raise RuntimeError(f"Ansible playbook failed: {e.stderr or e.stdout}")
        except FileNotFoundError:
            app_logger.error(f"Ansible command not found. Is Ansible installed and in PATH? Command: {command[0]}")
            raise RuntimeError("Ansible command not found. Please ensure Ansible is installed.")
        except Exception as e:
            app_logger.critical(f"An unexpected error occurred during Ansible execution: {e}", exc_info=True)
            raise RuntimeError(f"Unexpected error during Ansible execution: {e}")

    # --- New method to process collected data and store in PostgreSQL ---

    def _process_and_store_network_data(self, output_dir):
        """
        Processes collected network data from YAML/text files and stores it in the PostgreSQL database.
        This replaces the functionality of build_db.py.
        """
        app_logger.info("Starting network topology database build process in PostgreSQL.")

        try:
            # Clear existing data to ensure a fresh import.
            # IMPORTANT: This will delete all existing network topology data.
            # If you need to keep historical data or handle updates, this logic needs to be refined.
            db.session.query(RouteEntry).delete()
            db.session.query(ArpEntry).delete()
            db.session.query(Interface).delete()
            db.session.query(Device).delete()
            db.session.commit()
            app_logger.info("Cleared existing network topology data from PostgreSQL.")
        except Exception as e:
            db.session.rollback()
            app_logger.error(f"Error clearing existing network data: {e}", exc_info=True)
            raise RuntimeError(f"Failed to clear old network data: {e}")

        # Dictionary to hold processed data for each device
        device_files = {}

        # Scan the outputs directory for collected files
        for filename in os.listdir(output_dir):
            filepath = os.path.join(output_dir, filename)
            if not os.path.isfile(filepath):
                continue

            hostname = None
            device_type = None
            file_category = None

            # Determine hostname and device type based on filename conventions
            # Updated to match specific hostnames from your inventory.yml
            if filename.startswith('R') and ('_interfaces.yml' in filename or '_arp.txt' in filename or '_routes.txt' in filename):
                hostname_match = re.match(r'(R\d+)_', filename) # Matches R1, R2, R3
                if hostname_match:
                    hostname = hostname_match.group(1)
                device_type = "Router"
            elif filename.startswith('SW') and ('_interfaces.yml' in filename or '_arp.txt' in filename or '_routes.txt' in filename):
                hostname_match = re.match(r'(SW\d+)_', filename) # Matches SW1
                if hostname_match:
                    hostname = hostname_match.group(1)
                device_type = "Switch"
            elif filename.startswith('pafw_') and ('_interfaces.yml' in filename or '_arp.txt' in filename or '_routes.txt' in filename):
                hostname = "pafw" # Your inventory uses 'pafw' as hostname
                device_type = "Firewall"
            elif filename.startswith('fgt_') and ('_interfaces.yml' in filename or '_arp.yml' in filename or '_routes.yml' in filename):
                hostname = "fgt" # Your inventory uses 'fgt' as hostname
                device_type = "Firewall"

            # Determine file category
            if hostname: # Only proceed if hostname was successfully identified
                if '_interfaces.yml' in filename:
                    file_category = 'interfaces'
                elif '_arp.txt' in filename or '_arp.yml' in filename:
                    file_category = 'arp'
                elif '_routes.txt' in filename or '_routes.yml' in filename:
                    file_category = 'routes'

                if file_category:
                    if hostname not in device_files:
                        device_files[hostname] = {'type': device_type, 'interfaces': None, 'arp': None, 'routes': None}
                    device_files[hostname][file_category] = filepath # Store full path
                else:
                    app_logger.warning(f"File {filename} did not match a known category for hostname {hostname}. Skipping.")
            else:
                app_logger.warning(f"File {filename} did not match any known hostname pattern. Skipping.")

        app_logger.info(f"Discovered device files for processing: {json.dumps(device_files, indent=2)}")

        # Process data for each discovered device
        for hostname, files_info in device_files.items():
            app_logger.info(f"Attempting to process data for device: {hostname}")
            try:
                # Get or create the Device entry
                device = Device.query.filter_by(hostname=hostname).first()
                if not device:
                    device = Device(hostname=hostname, device_type=files_info['type'])
                    db.session.add(device)
                    db.session.flush() # Flush to get device.device_id
                    app_logger.info(f"Added new device '{hostname}' (ID: {device.device_id}) to session.")
                else:
                    app_logger.info(f"Device '{hostname}' (ID: {device.device_id}) already exists in DB.")

                # Process Interfaces
                if files_info.get('interfaces') and os.path.exists(files_info['interfaces']):
                    app_logger.info(f"Processing interfaces for {hostname} from {files_info['interfaces']}")
                    with open(files_info['interfaces'], 'r') as f:
                        interface_data = yaml.safe_load(f)
                        app_logger.debug(f"Raw interface data for {hostname}: {json.dumps(interface_data, indent=2)}")

                        if hostname.startswith('R') or hostname.startswith('SW'): # Cisco IOS facts format
                            interfaces_found = 0
                            # The main dictionary from ios_facts containing interface details is 'ansible_net_interfaces'
                            for intf_name, intf_details in interface_data.get('ansible_net_interfaces', {}).items():
                                app_logger.debug(f"Parsing interface '{intf_name}' details for {hostname}. Details: {json.dumps(intf_details)}")
                                for ip in intf_details.get('ipv4', []):
                                    address = ip.get('address')
                                    subnet_mask_prefix = ip.get('subnet') # Corrected key
                                    
                                    ipv4_subnet_cidr = None
                                    if address and subnet_mask_prefix:
                                        try:
                                            # Construct full CIDR (e.g., '10.0.1.0/24')
                                            network_obj = ipaddress.ip_network(f"{address}/{subnet_mask_prefix}", strict=False)
                                            ipv4_subnet_cidr = str(network_obj)
                                            app_logger.debug(f"Constructed CIDR for {intf_name}: {ipv4_subnet_cidr}")
                                        except ValueError:
                                            app_logger.warning(f"Invalid IP address or subnet mask for {intf_name} on {hostname}: {address}/{subnet_mask_prefix}")

                                    interface = Interface(
                                        device_id=device.device_id,
                                        name=intf_name,
                                        ipv4_address=address,
                                        ipv4_subnet=ipv4_subnet_cidr, # Use the constructed CIDR
                                        mac_address=intf_details.get('macaddress'),
                                        status=intf_details.get('operstatus'),
                                        type=intf_details.get('type')
                                    )
                                    db.session.add(interface)
                                    interfaces_found += 1
                                    app_logger.info(f"Added interface '{intf_name}' ({address}) for {hostname} to session.")
                            app_logger.info(f"Finished adding {interfaces_found} interfaces for {hostname}.")

                        elif hostname == 'pafw': # Palo Alto interfaces from panos_facts
                            interfaces_found = 0
                            for intf_details in interface_data.get('ansible_facts', {}).get('panos_interfaces', []):
                                app_logger.debug(f"Parsing Palo Alto interface '{intf_details.get('name')}' details: {json.dumps(intf_details)}")
                                if intf_details.get('ip'):
                                    # Palo Alto facts provide 'ip' and 'mask' separately
                                    ip_addr = intf_details.get('ip')
                                    mask_len = intf_details.get('mask') # This should be the prefix length
                                    
                                    ipv4_subnet_cidr = None
                                    if ip_addr and mask_len:
                                        try:
                                            # Assuming mask is already a prefix length like '24'
                                            network_obj = ipaddress.ip_network(f"{ip_addr}/{mask_len}", strict=False)
                                            ipv4_subnet_cidr = str(network_obj)
                                            app_logger.debug(f"Constructed CIDR for PA interface {intf_details.get('name')}: {ipv4_subnet_cidr}")
                                        except ValueError:
                                            app_logger.warning(f"Invalid PA IP/mask for {intf_details.get('name')}: {ip_addr}/{mask_len}")

                                    interface = Interface(
                                        device_id=device.device_id,
                                        name=intf_details.get('name'),
                                        ipv4_address=ip_addr,
                                        ipv4_subnet=ipv4_subnet_cidr,
                                        mac_address=intf_details.get('mac'),
                                        status=intf_details.get('state'),
                                        type='Ethernet' # Or parse from name/kind
                                    )
                                    db.session.add(interface)
                                    interfaces_found += 1
                                    app_logger.info(f"Added interface '{intf_details.get('name')}' ({ip_addr}) for {hostname} to session.")
                            app_logger.info(f"Finished adding {interfaces_found} interfaces for {hostname}.")

                        elif hostname == 'fgt': # FortiGate interfaces (adjust based on actual YAML structure)
                            interfaces_found = 0
                            for intf_name, intf_details in interface_data.get('interface', {}).items():
                                app_logger.debug(f"Parsing FortiGate interface '{intf_name}' details: {json.dumps(intf_details)}")
                                if 'ip' in intf_details:
                                    # FortiGate might give IP with CIDR directly like '192.168.1.1/24'
                                    full_ip_cidr = intf_details.get('ip')
                                    ip_addr = full_ip_cidr.split('/')[0] if '/' in full_ip_cidr else full_ip_cidr
                                    subnet_prefix = full_ip_cidr.split('/')[1] if '/' in full_ip_cidr else None

                                    ipv4_subnet_cidr = None
                                    if full_ip_cidr:
                                        try:
                                            network_obj = ipaddress.ip_network(full_ip_cidr, strict=False)
                                            ipv4_subnet_cidr = str(network_obj)
                                            app_logger.debug(f"Constructed CIDR for FGT interface {intf_name}: {ipv4_subnet_cidr}")
                                        except ValueError:
                                            app_logger.warning(f"Invalid FGT IP/CIDR for {intf_name}: {full_ip_cidr}")


                                    interface = Interface(
                                        device_id=device.device_id,
                                        name=intf_name,
                                        ipv4_address=ip_addr,
                                        ipv4_subnet=ipv4_subnet_cidr,
                                        mac_address=intf_details.get('mac'),
                                        status=intf_details.get('status'),
                                        type=intf_details.get('type')
                                    )
                                    db.session.add(interface)
                                    interfaces_found += 1
                                    app_logger.info(f"Added interface '{intf_name}' ({full_ip_cidr}) for {hostname} to session.")
                            app_logger.info(f"Finished adding {interfaces_found} interfaces for {hostname}.")
                    
                # Process ARP entries
                if files_info.get('arp') and os.path.exists(files_info['arp']):
                    app_logger.info(f"Processing ARP for {hostname} from {files_info['arp']}")
                    with open(files_info['arp'], 'r') as f:
                        arp_content = f.read()
                        app_logger.debug(f"Raw ARP data for {hostname}:\n{arp_content}")
                        arp_entries_found = 0
                        if hostname.startswith('R') or hostname.startswith('SW'): # Cisco IOS 'show ip arp' output
                            for line in arp_content.splitlines():
                                # Adjusted regex to be more robust, and capture optional interface
                                match = re.match(r'Internet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})(?:\s+\S+\s+\S+\s+(\S+))?', line)
                                if match:
                                    ip, mac_cisco, interface_name = match.groups()
                                    mac = mac_cisco.replace('.', '')
                                    arp_entry = ArpEntry(
                                        device_id=device.device_id,
                                        ip_address=ip,
                                        mac_address=mac,
                                        interface_name=interface_name if interface_name else None
                                    )
                                    db.session.add(arp_entry)
                                    arp_entries_found += 1
                                    app_logger.info(f"Added ARP entry {ip} ({mac}) on {hostname} to session.")
                            app_logger.info(f"Finished adding {arp_entries_found} ARP entries for {hostname}.")

                        elif hostname == 'pafw': # Palo Alto ARP (XML output)
                            # Assuming XML output structure is consistent with panos_op <show><arp><entry name='all'/>
                            try:
                                import xml.etree.ElementTree as ET
                                root = ET.fromstring(arp_content)
                                for entry_element in root.findall(".//entry"):
                                    ip = entry_element.findtext('ip')
                                    mac = entry_element.findtext('mac')
                                    interface = entry_element.findtext('interface')
                                    if ip and mac:
                                        arp_entry = ArpEntry(
                                            device_id=device.device_id,
                                            ip_address=ip,
                                            mac_address=mac,
                                            interface_name=interface
                                        )
                                        db.session.add(arp_entry)
                                        arp_entries_found += 1
                                        app_logger.info(f"Added PA ARP entry {ip} ({mac}) on {hostname} to session.")
                                app_logger.info(f"Finished adding {arp_entries_found} ARP entries for {hostname}.")
                            except Exception as parse_e:
                                app_logger.error(f"Error parsing Palo Alto ARP XML for {hostname}: {parse_e}", exc_info=True)


                        elif hostname == 'fgt': # FortiGate ARP (YAML)
                            arp_data = yaml.safe_load(arp_content)
                            arp_entries_found = 0
                            for entry in arp_data.get('arp_table', []):
                                arp_entry = ArpEntry(
                                    device_id=device.device_id,
                                    ip_address=entry.get('ip'),
                                    mac_address=entry.get('mac'),
                                    interface_name=entry.get('interface')
                                )
                                db.session.add(arp_entry)
                                arp_entries_found += 1
                                app_logger.info(f"Added FGT ARP entry {entry.get('ip')} ({entry.get('mac')}) on {hostname} to session.")
                            app_logger.info(f"Finished adding {arp_entries_found} ARP entries for {hostname}.")

                # Process Route entries
                if files_info.get('routes') and os.path.exists(files_info['routes']):
                    app_logger.info(f"Processing routes for {hostname} from {files_info['routes']}")
                    with open(files_info['routes'], 'r') as f:
                        route_content = f.read()
                        app_logger.debug(f"Raw Route data for {hostname}:\n{route_content}")
                        route_entries_found = 0
                        if hostname.startswith('R') or hostname.startswith('SW'): # Cisco IOS 'show ip route' output
                            for line in route_content.splitlines():
                                # Example: "S* 0.0.0.0/0 [1/0] via 10.0.0.1, GigabitEthernet0/0"
                                # Example: "C        10.0.0.0/24 is directly connected, GigabitEthernet0/0"
                                # Regex adapted to match common Cisco route output and handle optional elements
                                match = re.match(r'^(?:[CDLSRI]\*?|O|E[12]|N[12]|P|i|X|H|a|b|%+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})(?: \[(\d+)\/(\d+)\])?(?: via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?,?\s*(.+)?', line.strip())
                                if match:
                                    network = match.group(1)
                                    admin_distance = match.group(2)
                                    metric = match.group(3)
                                    next_hop = match.group(4)
                                    interface_name_raw = match.group(5)
                                    
                                    # Simple heuristic for route_type based on common Cisco flags
                                    route_type = 'unknown'
                                    if line.strip().startswith('C'): route_type = 'connected'
                                    elif line.strip().startswith('S'): route_type = 'static'
                                    elif line.strip().startswith('O'): route_type = 'ospf'
                                    elif line.strip().startswith('B'): route_type = 'bgp'
                                    elif line.strip().startswith('R'): route_type = 'rip'

                                    route_entry = RouteEntry(
                                        device_id=device.device_id,
                                        destination_network=network,
                                        next_hop=next_hop,
                                        admin_distance=int(admin_distance) if admin_distance else None,
                                        metric=int(metric) if metric else None,
                                        interface_name=interface_name_raw.strip() if interface_name_raw else None,
                                        route_type=route_type,
                                        flags=line.strip().split(' ')[0] # Capture the initial flag
                                    )
                                    db.session.add(route_entry)
                                    route_entries_found += 1
                                    app_logger.info(f"Added route {network} via {next_hop} on {hostname} to session.")
                            app_logger.info(f"Finished adding {route_entries_found} route entries for {hostname}.")

                        elif hostname == 'pafw': # Palo Alto routes (XML/text output)
                            # This parsing needs to be adapted based on the exact output format of panos_op 'show routing route'
                            # The 'content' from panos_op might be XML.
                            try:
                                import xml.etree.ElementTree as ET
                                root = ET.fromstring(route_content)
                                # Assuming a structure like <result><route>...</route></result>
                                for route_element in root.findall(".//route"): # Adjust XPath based on actual XML
                                    destination = route_element.findtext('destination')
                                    next_hop = route_element.findtext('nexthop')
                                    interface = route_element.findtext('interface')
                                    route_type = route_element.findtext('type') # e.g., 'static', 'direct'
                                    if destination and next_hop:
                                        route_entry = RouteEntry(
                                            device_id=device.device_id,
                                            destination_network=destination,
                                            next_hop=next_hop,
                                            interface_name=interface,
                                            route_type=route_type
                                        )
                                        db.session.add(route_entry)
                                        route_entries_found += 1
                                        app_logger.info(f"Added PA route {destination} via {next_hop} on {hostname} to session.")
                                app_logger.info(f"Finished adding {route_entries_found} route entries for {hostname}.")
                            except Exception as parse_e:
                                app_logger.error(f"Error parsing Palo Alto routes XML for {hostname}: {parse_e}", exc_info=True)


                        elif hostname == 'fgt': # FortiGate routes (YAML)
                            route_data = yaml.safe_load(route_content)
                            route_entries_found = 0
                            for entry in route_data.get('routes', []): # This assumes the FortiGate returns a list of routes under 'routes' key
                                route_entry = RouteEntry(
                                    device_id=device.device_id,
                                    destination_network=entry.get('destination'),
                                    next_hop=entry.get('gateway'),
                                    interface_name=entry.get('interface'),
                                    route_type=entry.get('type') # 'static', 'connect', etc.
                                )
                                db.session.add(route_entry)
                                route_entries_found += 1
                                app_logger.info(f"Added FGT route {entry.get('destination')} via {entry.get('gateway')} on {hostname} to session.")
                            app_logger.info(f"Finished adding {route_entries_found} route entries for {hostname}.")
                
                db.session.commit() # Commit all changes for this specific device
                app_logger.info(f"Successfully committed data for device: {hostname}")

            except Exception as e:
                db.session.rollback() # Rollback if any error occurs during processing a single device
                app_logger.error(f"Error processing data for device {hostname}: {e}", exc_info=True)
                # DO NOT raise here. Continue to process other devices.
                continue 

        app_logger.info("Network topology database build process completed.")

    def run_data_collection(self):
        """
        Executes the Ansible collector playbook and then processes the collected data
        into the PostgreSQL database.
        """
        app_logger.info("Running Ansible network data collector (collector.yml)...")
        try:
            # The collector playbook saves outputs to OUTPUTS_DIR, so we don't need its stdout/stderr here
            # beyond just checking for successful execution.
            stdout, stderr = self._execute_ansible_playbook('collector.yml')
            app_logger.info("Network data collection completed.")
            
            # Now, process these files and store them in the database
            self._process_and_store_network_data(OUTPUTS_DIR)
            app_logger.info("Network topology database built successfully.")

        except RuntimeError as e:
            app_logger.error(f"Network data collection or processing failed: {e}")
            raise
        except Exception as e:
            app_logger.critical(f"An unexpected error occurred during network data collection/processing: {e}", exc_info=True)
            raise


    # --- Placeholder for Pathfinding Logic ---
    def _find_network_path_in_db(self, source_ip, destination_ip):
        """
        Finds a network path between source and destination IPs using the data
        stored in the PostgreSQL database.
        This replaces the functionality of pathfinder.py.
        """
        app_logger.info(f"Starting pathfinding from {source_ip} to {destination_ip} using DB data.")
        
        # This is a placeholder. The actual pathfinding logic will be implemented here
        # using Device, Interface, ArpEntry, RouteEntry models.
        # This will involve graph traversal algorithms (e.g., BFS/DFS).
        # For now, it will return a dummy response or raise an error.

        path = [] # List of tuples: (device_hostname, outgoing_interface, next_hop_ip, route_type)
        firewalls_in_path = [] # List of firewall hostnames

        try:
            source_ip_obj = ipaddress.ip_address(source_ip)
            destination_ip_obj = ipaddress.ip_address(destination_ip)
        except ipaddress.AddressValueError:
            return "Error: Invalid IP address format. Please enter valid IPv4 addresses.", []

        # --- Simplified Pathfinding Logic Placeholder ---
        # This is a very basic, non-recursive example.
        # A real pathfinder would use BFS/DFS on the interconnected devices.

        # 1. Try to find the device directly connected to the source_ip
        src_device = None
        src_interface = None
        # Check interfaces directly
        intf = Interface.query.filter(
            Interface.ipv4_address == str(source_ip_obj)
        ).first()
        if intf:
            src_device = Device.query.get(intf.device_id)
            src_interface = intf.name
        
        if not src_device:
            # If not directly on an interface, check for a subnet it belongs to
            # This is more complex and would involve iterating subnets and checking if IP is in range.
            # For simplicity, let's assume direct interface or next-hop is known.
            # Or perhaps check ARP entries if source is a host behind a device.
            pass # Placeholder for more complex source device lookup

        if not src_device:
            app_logger.warning(f"Source IP {source_ip} not found on any device interface.")
            return f"Pathfinding failed: Source IP {source_ip} not found on any device interface.", []

        path.append((src_device.hostname, src_interface, str(source_ip_obj), 'source'))
        
        current_ip = source_ip_obj
        current_device = src_device
        
        # Simple loop: find next hop from current device until destination is reached or no more routes
        max_hops = 10 # Prevent infinite loops
        for _ in range(max_hops):
            if current_ip == destination_ip_obj:
                break # Destination reached

            # Check if current_ip is directly connected to destination_ip on current_device (ARP/Interface)
            # (Simplified: A real check would involve direct subnet connectivity)

            # Find a route from current_device to destination_ip
            # Prioritize more specific routes (longer prefix)
            routes = RouteEntry.query.filter(
                RouteEntry.device_id == current_device.device_id
            ).order_by(sa.desc(func.length(RouteEntry.destination_network))).all() # Order by prefix length

            next_hop_found = False
            for route in routes:
                try:
                    dest_net = ipaddress.ip_network(route.destination_network)
                    if destination_ip_obj in dest_net:
                        # Found a route to the destination network
                        if route.next_hop:
                            next_hop_ip = ipaddress.ip_address(route.next_hop)
                            path.append((current_device.hostname, route.interface_name, str(next_hop_ip), route.route_type))
                            
                            # Find the device associated with this next_hop_ip (its interface)
                            next_intf = Interface.query.filter(Interface.ipv4_address == str(next_hop_ip)).first()
                            if next_intf:
                                current_device = Device.query.get(next_intf.device_id)
                                current_ip = next_hop_ip
                                next_hop_found = True
                                break
                            else:
                                # Next hop is outside known topology or a host, path terminates
                                path.append((f"Unknown device/host for {str(next_hop_ip)}", "N/A", "N/A", "Path Terminated"))
                                next_hop_found = True
                                break # Path ends here if next hop device is unknown
                        else:
                            # Directly connected route to destination (current_device is last hop)
                            path.append((current_device.hostname, route.interface_name, str(destination_ip_obj), 'direct_connect'))
                            current_ip = destination_ip_obj # Destination reached
                            next_hop_found = True
                            break
                except ipaddress.AddressValueError:
                    app_logger.warning(f"Invalid network format in route entry: {route.destination_network}")
                    continue

            if not next_hop_found:
                app_logger.warning(f"No route found from {current_device.hostname} for destination {destination_ip}.")
                break # No route found, path terminates

            if current_ip == destination_ip_obj:
                break # Destination reached

        if current_ip != destination_ip_obj:
            app_logger.warning(f"Pathfinding stopped before reaching destination: {destination_ip_obj}")
            return f"Pathfinding failed: Could not reach {destination_ip}.", []

        # Identify firewalls in the path
        firewalls_in_path = [
            hop[0] for hop in path 
            if Device.query.filter_by(hostname=hop[0]).first() and 
               Device.query.filter_by(hostname=hop[0]).first().device_type == "Firewall"
        ]

        app_logger.info(f"Path found. Firewalls in path: {firewalls_in_path}")
        return path, firewalls_in_path

    # --- Update methods that use the old subprocess calls ---
    def perform_pre_check(self, rule_data, firewalls_involved):
        """
        Performs pre-checks on relevant firewalls.
        Now also includes internal pathfinding using the DB.
        """
        app_logger.info(f"Performing pre-check for rule {rule_data['rule_id']} on firewalls: {firewalls_involved}")

        pre_check_stdout = ""
        pre_check_stderr = ""
        
        # Step 1: Run data collection and build internal DB if not recently done
        # Consider adding a timestamp or flag to avoid frequent collection for performance
        try:
            self.run_data_collection()
        except Exception as e:
            app_logger.error(f"Initial network data collection failed during pre-check: {e}")
            raise RuntimeError(f"Pre-check failed: Network data collection failed. {e}")

        # Step 2: Perform pathfinding using the internal DB
        app_logger.info(f"Performing pathfinding from {rule_data['source_ip']} to {rule_data['destination_ip']}.")
        path, discovered_firewalls = self._find_network_path_in_db(
            rule_data['source_ip'], rule_data['destination_ip']
        )
        
        if isinstance(path, str): # Pathfinding returned an error message
            app_logger.error(f"Pathfinding failed: {path}")
            raise RuntimeError(f"Pre-check failed: Pathfinding error: {path}")

        app_logger.info(f"Pathfinding completed. Discovered firewalls in path: {discovered_firewalls}")
        rule_data['firewalls_involved'] = discovered_firewalls # Update rule_data with discovered firewalls

        # Filter firewalls for pre-check to only those involved AND provided in the input list
        firewalls_for_precheck = [fw for fw in firewalls_involved if fw in discovered_firewalls]

        if not firewalls_for_precheck:
            app_logger.warning(f"No firewalls identified for pre-check between {rule_data['source_ip']} and {rule_data['destination_ip']} from the provided list.")
            # If no firewalls are involved, but the request still makes sense (e.g., internal host-to-host)
            # we might want to skip further pre-checks and mark as 'No Provisioning Needed'.
            return "No firewalls in path require pre-check based on current network topology. Skipping pre-checks.", "", []

        for firewall_name in firewalls_for_precheck:
            extra_vars = {
                'firewall_name': firewall_name,
                'source_ip': rule_data['source_ip'],
                'destination_ip': rule_data['destination_ip'],
                'protocol': rule_data['protocol'],
                'port': rule_data['ports'][0] if rule_data['ports'] else 'any' # Assuming first port for pre-check
            }

            playbook = None
            if 'pa' in firewall_name.lower():
                playbook = 'pre_check_firewall_rule_paloalto.yml'
            elif 'fgt' in firewall_name.lower():
                playbook = 'pre_check_firewall_rule_fortinet.yml'
            else:
                app_logger.warning(f"Unknown firewall type for {firewall_name}. Skipping pre-check.")
                continue

            app_logger.info(f"Pre-checking rule {rule_data['rule_id']} on {firewall_name} using {playbook}...")
            try:
                stdout, stderr = self._execute_ansible_playbook(playbook, extra_vars=extra_vars)
                pre_check_stdout += f"\n--- {firewall_name} STDOUT ---\n" + stdout
                pre_check_stderr += f"\n--- {firewall_name} STDERR ---\n" + stderr

                if "POLICY_EXISTS" in stdout:
                    app_logger.info(f"Rule {rule_data['rule_id']} already exists on {firewall_name}.")
                    # Add to already_configured list if policy exists
                    if 'firewalls_already_configured' not in rule_data or rule_data['firewalls_already_configured'] is None:
                        rule_data['firewalls_already_configured'] = []
                    rule_data['firewalls_already_configured'].append(firewall_name)
                else:
                    app_logger.info(f"Rule {rule_data['rule_id']} does NOT exist on {firewall_name}.")
                    # Add to firewalls_to_provision if policy doesn't exist
                    if 'firewalls_to_provision' not in rule_data or rule_data['firewalls_to_provision'] is None:
                        rule_data['firewalls_to_provision'] = []
                    rule_data['firewalls_to_provision'].append(firewall_name)

            except RuntimeError as e:
                app_logger.error(f"Failed to pre-check rule {rule_data['rule_id']} on {firewall_name}: {e}")
                # Don't re-raise, allow other pre-checks to run.
                # The calling function will need to check the status of firewalls_to_provision/already_configured.
            except Exception as e:
                app_logger.critical(f"An unexpected error occurred during pre-check for rule {rule_data['rule_id']} on {firewall_name}: {e}")
                # Don't re-raise
        
        # Return combined output and the potentially modified rule_data
        return pre_check_stdout, pre_check_stderr, firewalls_for_precheck


    def provision_firewall_rule(self, rule_data, firewalls_to_provision):
        """
        Provisions a firewall rule on specified firewalls.
        """
        app_logger.info(f"Attempting to provision rule {rule_data['rule_id']} on firewalls: {firewalls_to_provision}")
        provision_stdout = ""
        provision_stderr = ""
        
        successfully_provisioned = []
        failed_provisioning = []

        if not firewalls_to_provision:
            app_logger.info(f"No firewalls specified for provisioning for rule {rule_data['rule_id']}. Skipping provisioning.")
            return "No firewalls to provision.", "", [], []

        for firewall_name in firewalls_to_provision:
            extra_vars = {
                'firewall_name': firewall_name,
                'rule_id': rule_data['rule_id'],
                'source_ip': rule_data['source_ip'],
                'destination_ip': rule_data['destination_ip'],
                'protocol': rule_data['protocol'],
                'dest_port': rule_data['ports'][0] if rule_data['ports'] else 'any', # Assuming first port for provisioning
                'rule_description': rule_data['rule_description']
            }

            playbook = None
            if 'pa' in firewall_name.lower():
                playbook = 'provision_firewall_rule_paloalto.yml'
            elif 'fgt' in firewall_name.lower():
                playbook = 'provision_firewall_rule_fortinet.yml'
            else:
                app_logger.warning(f"Unknown firewall type for {firewall_name}. Skipping provisioning.")
                failed_provisioning.append(firewall_name)
                continue

            app_logger.info(f"Provisioning rule {rule_data['rule_id']} on {firewall_name} using {playbook}...")
            try:
                stdout, stderr = self._execute_ansible_playbook(playbook, extra_vars=extra_vars)
                provision_stdout += f"\n--- {firewall_name} STDOUT ---\n" + stdout
                provision_stderr += f"\n--- {firewall_name} STDERR ---\n" + stderr
                app_logger.info(f"Rule {rule_data['rule_id']} successfully provisioned on {firewall_name}.")
                successfully_provisioned.append(firewall_name)
            except RuntimeError as e:
                app_logger.error(f"Failed to provision rule {rule_data['rule_id']} on {firewall_name}: {e}")
                failed_provisioning.append(firewall_name)
                provision_stderr += f"\n--- {firewall_name} ERROR ---\n" + str(e)
            except Exception as e:
                app_logger.critical(f"An unexpected error occurred during provisioning for rule {rule_data['rule_id']} on {firewall_name}: {e}")
                failed_provisioning.append(firewall_name)
                provision_stderr += f"\n--- {firewall_name} UNEXPECTED ERROR ---\n" + str(e)

        return provision_stdout, provision_stderr, successfully_provisioned, failed_provisioning


    def perform_post_check(self, rule_data, provisioned_firewalls):
        """
        Performs post-checks on firewalls where rules were provisioned.
        """
        app_logger.info(f"Performing post-check for rule {rule_data['rule_id']} on firewalls: {provisioned_firewalls}")
        post_check_stdout = ""
        post_check_stderr = ""
        
        verified_firewalls = []
        unverified_firewalls = []

        if not provisioned_firewalls:
            app_logger.info(f"No firewalls specified for post-check for rule {rule_data['rule_id']}. Skipping post-checks.")
            return "No firewalls to post-check.", ""

        for firewall_name in provisioned_firewalls:
            extra_vars = {
                'firewall_name': firewall_name,
                'rule_id': rule_data['rule_id'],
                'source_ip': rule_data['source_ip'],
                'destination_ip': rule_data['destination_ip'],
                'protocol': rule_data['protocol'],
                'dest_port': rule_data['ports'][0] if rule_data['ports'] else 'any' # Assuming first port for post-check
            }

            playbook = None
            if 'pa' in firewall_name.lower():
                playbook = 'post_check_firewall_rule_paloalto.yml'
            elif 'fgt' in firewall_name.lower():
                playbook = 'post_check_firewall_rule_fortinet.yml'
            else:
                app_logger.warning(f"Unknown firewall type for {firewall_name}. Skipping post-check.")
                unverified_firewalls.append(firewall_name)
                continue

            app_logger.info(f"Post-checking rule {rule_data['rule_id']} on {firewall_name} using {playbook}...")
            try:
                stdout, stderr = self._execute_ansible_playbook(playbook, extra_vars=extra_vars)
                post_check_stdout += f"\n--- {firewall_name} STDOUT ---\n" + stdout
                post_check_stderr += f"\n--- {firewall_name} STDERR ---\n" + stderr
                
                # Check for a specific string in stdout indicating successful post-check
                if "POLICY_VERIFIED" in stdout: # Playbook should output this if verification passes
                    app_logger.info(f"Rule {rule_data['rule_id']} successfully verified on {firewall_name}.")
                    verified_firewalls.append(firewall_name)
                else:
                    app_logger.warning(f"Rule {rule_data['rule_id']} NOT verified on {firewall_name}. Check Ansible output.")
                    unverified_firewalls.append(firewall_name)
                    # Don't raise here, let the process continue to check other firewalls
                    # raise RuntimeError(f"Post-check verification failed on {firewall_name}.")

            except RuntimeError as e:
                app_logger.error(f"Failed to post-check rule {rule_data['rule_id']} on {firewall_name}: {e}")
                unverified_firewalls.append(firewall_name)
                post_check_stderr += f"\n--- {firewall_name} ERROR ---\n" + str(e)
            except Exception as e:
                app_logger.critical(f"An unexpected error occurred during post-check for rule {rule_data['rule_id']} on {firewall_name}: {e}")
                unverified_firewalls.append(firewall_name)
                post_check_stderr += f"\n--- {firewall_name} UNEXPECTED ERROR ---\n" + str(e)

        # You might want to return verified_firewalls and unverified_firewalls lists
        # to the caller so it can update the FirewallRule status more granularly.
        return post_check_stdout, post_check_stderr, verified_firewalls, unverified_firewalls

