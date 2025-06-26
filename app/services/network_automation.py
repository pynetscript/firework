import subprocess
import os
import json
import logging
import yaml # Needed for parsing Ansible output files
import ipaddress # For IP address validation and manipulation
import re # For regex parsing
from sqlalchemy import func # For database functions like length for ordering

# Import Flask-SQLAlchemy db instance and the new models
from app.models import db, Device, Interface, ArpEntry, RouteEntry

app_logger = logging.getLogger(__name__)

app_logger.debug(f"DEBUG: network_automation.py is being loaded from: {os.path.abspath(__file__)}")

class NetworkAutomationService:
    def __init__(self, inventory_path='inventory.yml', playbook_dir='.'):
        project_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
        self.inventory_path = os.path.join(project_root, inventory_path)
        self.playbook_dir = os.path.join(project_root, playbook_dir)
        
        self.outputs_dir = os.path.join(project_root, 'outputs')
        app_logger.info(f"Ansible outputs directory set to: {self.outputs_dir}")

        self.ansible_tmp_dir = os.path.join(project_root, 'ansible_tmp')

        if not os.path.exists(self.inventory_path):
            app_logger.error(f"Inventory file not found at: {self.inventory_path}")
            raise FileNotFoundError(f"Inventory file not found at: {self.inventory_path}")

        os.makedirs(self.outputs_dir, exist_ok=True)
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
        
        env['ANSIBLE_HOST_KEY_CHECKING'] = 'False'
        env['ANSIBLE_COLLECTIONS_PATH'] = os.path.join(self.playbook_dir, 'ansible_collections')
        if 'ANSIBLE_COLLECTIONS_PATHS' in env:
            del env['ANSIBLE_COLLECTIONS_PATHS']

        env['ANSIBLE_CACHE_DIR'] = os.path.join(self.ansible_tmp_dir, 'cache')
        env['ANSIBLE_TMPDIR'] = self.ansible_tmp_dir
        env['TMPDIR'] = self.ansible_tmp_dir

        app_logger.debug("--- Subprocess Environment for Ansible ---")
        for k, v in env.items():
            if k in ['PATH', 'USER', 'HOME', 'ANSIBLE_CACHE_DIR', 'ANSIBLE_TMPDIR', 'TMPDIR', 'ANSIBLE_COLLECTIONS_PATH', 'ANSIBLE_HOST_KEY_CHECKING']:
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


    def run_data_collection(self):
        """
        Runs the Ansible collector playbook and then processes its output
        to populate the network topology database.
        """
        app_logger.info("Running Ansible network data collector (collector.yml)...")
        try:
            stdout, stderr = self._execute_ansible_playbook('collector.yml')
            app_logger.info("Network data collection completed.")
            # After collection, process and store the data in the DB
            self._process_and_store_network_data(self.outputs_dir)
        except RuntimeError as e:
            app_logger.error(f"Network data collection or processing failed: {e}")
            raise RuntimeError(f"Network data collection or processing failed: {e}")
        except Exception as e:
            app_logger.critical(f"An unexpected error occurred during network data collection/processing: {e}", exc_info=True)
            raise RuntimeError(f"An unexpected error occurred during network data collection/processing: {e}")

    def _process_and_store_network_data(self, output_dir):
        """
        Processes collected network data from YAML/text files and stores it in the PostgreSQL database.
        This replaces the functionality of build_db.py.
        """
        app_logger.info("Starting network topology database build process in PostgreSQL.")

        # --- DEBUGGING ADDITIONS ---
        app_logger.info(f"Attempting to list directory: {output_dir}")
        try:
            files_in_output_dir = os.listdir(output_dir)
            app_logger.info(f"Files found in {output_dir}: {files_in_output_dir}")
            if not files_in_output_dir:
                app_logger.warning(f"Directory {output_dir} appears empty to Python process. This is unexpected for data processing.")
        except FileNotFoundError:
            app_logger.error(f"Output directory not found: {output_dir}. Please ensure it exists and has correct read/write permissions.")
            raise
        except PermissionError as e:
            app_logger.error(f"Permission denied when trying to list {output_dir}: {e}. Ensure Flask/Gunicorn user has read permissions.")
            raise
        # --- END DEBUGGING ADDITIONS ---

        try:
            # Clear existing data to ensure a fresh import.
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
        for filename in files_in_output_dir:
            filepath = os.path.join(output_dir, filename)
            if not os.path.isfile(filepath): # Ensure it's a file, not a directory
                continue

            hostname = None
            device_type = None
            file_category = None

            # Determine file category first
            if '_interfaces.yml' in filename:
                file_category = 'interfaces'
            elif '_arp.txt' in filename or '_arp.yml' in filename: # .yml for FGT, .txt for PA/Cisco
                file_category = 'arp'
            elif '_routes.txt' in filename or '_routes.yml' in filename: # .yml for FGT, .txt for PA/Cisco
                file_category = 'routes'
            
            if file_category: # If it's a file we care about based on its content type
                # Now determine the hostname based on naming convention
                if filename.startswith('R') and file_category in ['interfaces', 'arp', 'routes']:
                    hostname_match = re.match(r'(R\d+)_', filename)
                    if hostname_match:
                        hostname = hostname_match.group(1)
                        device_type = "Router"
                elif filename.startswith('SW') and file_category in ['interfaces', 'arp', 'routes']:
                    hostname_match = re.match(r'(SW\d+)_', filename)
                    if hostname_match:
                        hostname = hostname_match.group(1)
                        device_type = "Switch"
                elif filename.startswith('pafw_') and file_category in ['interfaces', 'arp', 'routes']:
                    hostname = "pafw"
                    device_type = "Firewall"
                elif filename.startswith('fgt_') and file_category in ['interfaces', 'arp', 'routes']:
                    hostname = "fgt"
                    device_type = "Firewall"

                if hostname: # If a hostname was successfully identified for this file
                    if hostname not in device_files:
                        device_files[hostname] = {'type': device_type, 'interfaces': None, 'arp': None, 'routes': None}
                    device_files[hostname][file_category] = filepath
                else:
                    app_logger.warning(f"File {filename} matched a category but its hostname pattern was not recognized. Skipping.")
            else:
                app_logger.debug(f"File {filename} did not match any known file category. Skipping.")

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
                        # --- MODIFIED: Load as JSON for Palo Alto, YAML for others ---
                        if hostname == 'pafw':
                            interface_data = json.load(f)
                        else:
                            interface_data = yaml.safe_load(f)
                        # --- END MODIFIED ---
                        app_logger.debug(f"Raw interface data for {hostname}: {json.dumps(interface_data, indent=2)}")

                        if hostname.startswith('R') or hostname.startswith('SW'): # Cisco IOS facts format
                            interfaces_found = 0
                            for intf_name, intf_details in interface_data.get('ansible_net_interfaces', {}).items():
                                app_logger.debug(f"Parsing interface '{intf_name}' details for {hostname}. Details: {json.dumps(intf_details)}")
                                for ip in intf_details.get('ipv4', []):
                                    address = ip.get('address')
                                    subnet_mask_prefix = ip.get('subnet')
                                    
                                    ipv4_subnet_cidr = None
                                    if address and subnet_mask_prefix:
                                        try:
                                            network_obj = ipaddress.ip_network(f"{address}/{subnet_mask_prefix}", strict=False)
                                            ipv4_subnet_cidr = str(network_obj)
                                            app_logger.debug(f"Constructed CIDR for {intf_name}: {ipv4_subnet_cidr}")
                                        except ValueError:
                                            app_logger.warning(f"Invalid IP address or subnet mask for {intf_name} on {hostname}: {address}/{subnet_mask_prefix}")

                                    interface = Interface(
                                        device_id=device.device_id,
                                        name=intf_name,
                                        ipv4_address=address,
                                        ipv4_subnet=ipv4_subnet_cidr,
                                        mac_address=intf_details.get('macaddress'),
                                        status=intf_details.get('operstatus'),
                                        type=intf_details.get('type')
                                    )
                                    db.session.add(interface)
                                    interfaces_found += 1
                                    app_logger.info(f"Added interface '{intf_name}' ({address}) for {hostname} to session.")
                            app_logger.info(f"Finished adding {interfaces_found} interfaces for {hostname}.")

                        elif hostname == 'pafw': # Palo Alto interfaces from panos_facts (JSON structure)
                            interfaces_found = 0
                            # Data is under 'ansible_facts.ansible_net_interfaces'
                            for intf_details in interface_data.get('ansible_facts', {}).get('ansible_net_interfaces', []):
                                app_logger.debug(f"Parsing Palo Alto interface '{intf_details.get('name')}' details: {json.dumps(intf_details)}")
                                
                                # Palo Alto 'ip' key contains a list of CIDR strings (e.g., "10.11.0.2/30")
                                for full_ip_cidr in intf_details.get('ip', []):
                                    ip_addr = full_ip_cidr.split('/')[0] if '/' in full_ip_cidr else full_ip_cidr
                                    
                                    ipv4_subnet_cidr = None
                                    if full_ip_cidr:
                                        try:
                                            network_obj = ipaddress.ip_network(full_ip_cidr, strict=False)
                                            ipv4_subnet_cidr = str(network_obj)
                                            app_logger.debug(f"Constructed CIDR for PA interface {intf_details.get('name')}: {ipv4_subnet_cidr}")
                                        except ValueError:
                                            app_logger.warning(f"Invalid PA IP/mask for {intf_details.get('name')}: {full_ip_cidr}")

                                    interface = Interface(
                                        device_id=device.device_id,
                                        name=intf_details.get('name'),
                                        ipv4_address=ip_addr,
                                        ipv4_subnet=ipv4_subnet_cidr,
                                        # These fields might not always be directly available in panos_facts simplified output
                                        mac_address=intf_details.get('mac'),
                                        status=intf_details.get('state'), 
                                        type='Ethernet' # Default, or try to derive
                                    )
                                    db.session.add(interface)
                                    interfaces_found += 1
                                    app_logger.info(f"Added interface '{intf_details.get('name')}' ({full_ip_cidr}) for {hostname} to session.")
                            app_logger.info(f"Finished adding {interfaces_found} interfaces for {hostname}.")

                        elif hostname == 'fgt': # FortiGate interfaces (adjust based on actual YAML structure)
                            interfaces_found = 0
                            for intf_name, intf_details in interface_data.get('interface', {}).items():
                                app_logger.debug(f"Parsing FortiGate interface '{intf_name}' details: {json.dumps(intf_details)}")
                                if 'ip' in intf_details:
                                    full_ip_cidr = intf_details.get('ip')
                                    ip_addr = full_ip_cidr.split('/')[0] if '/' in full_ip_cidr else full_ip_cidr

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

                        elif hostname == 'pafw': # Palo Alto ARP (JSON output)
                            try:
                                arp_data = json.loads(arp_content) # Load as JSON
                                # Access the ARP entries: response.result.entries.entry
                                for entry in arp_data.get('response', {}).get('result', {}).get('entries', {}).get('entry', []):
                                    ip = entry.get('ip')
                                    mac = entry.get('mac')
                                    interface = entry.get('interface')
                                    if ip and mac:
                                        arp_entry = ArpEntry(
                                            device_id=device.device_id,
                                            ip_address=ip,
                                            mac_address=mac.replace(':', ''), # Remove colons for consistency
                                            interface_name=interface
                                        )
                                        db.session.add(arp_entry)
                                        arp_entries_found += 1
                                        app_logger.info(f"Added PA ARP entry {ip} ({mac}) on {hostname} to session.")
                                app_logger.info(f"Finished adding {arp_entries_found} ARP entries for {hostname}.")
                            except Exception as parse_e:
                                app_logger.error(f"Error parsing Palo Alto ARP JSON for {hostname}: {parse_e}", exc_info=True)


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
                                        flags=line.strip().split(' ')[0]
                                    )
                                    db.session.add(route_entry)
                                    route_entries_found += 1
                                    app_logger.info(f"Added route {network} via {next_hop} on {hostname} to session.")
                            app_logger.info(f"Finished adding {route_entries_found} route entries for {hostname}.")

                        elif hostname == 'pafw': # Palo Alto routes (JSON output)
                            try:
                                route_data = json.loads(route_content) # Load as JSON
                                # Access the route entries: response.result.entry
                                for entry in route_data.get('response', {}).get('result', {}).get('entry', []):
                                    destination = entry.get('destination')
                                    next_hop = entry.get('nexthop')
                                    interface = entry.get('interface')
                                    flags = entry.get('flags', '') # Get flags string, default to empty
                                    
                                    # Simple heuristic to derive a more readable route_type from flags
                                    readable_route_type = 'unknown'
                                    if 'C' in flags: readable_route_type = 'connected'
                                    elif 'S' in flags: readable_route_type = 'static'
                                    elif 'O' in flags: readable_route_type = 'ospf'
                                    elif 'B' in flags: readable_route_type = 'bgp'
                                    elif 'R' in flags: readable_route_type = 'rip' # If rip supported

                                    if destination: # next_hop can be "0.0.0.0" for directly connected
                                        route_entry = RouteEntry(
                                            device_id=device.device_id,
                                            destination_network=destination,
                                            next_hop=next_hop if next_hop != '0.0.0.0' else None, # Store None if directly connected
                                            interface_name=interface,
                                            route_type=readable_route_type,
                                            flags=flags # Store raw flags too
                                        )
                                        db.session.add(route_entry)
                                        route_entries_found += 1
                                        app_logger.info(f"Added PA route {destination} via {next_hop} on {hostname} to session.")
                                app_logger.info(f"Finished adding {route_entries_found} route entries for {hostname}.")
                            except Exception as parse_e:
                                app_logger.error(f"Error parsing Palo Alto routes JSON for {hostname}: {parse_e}", exc_info=True)


                        elif hostname == 'fgt': # FortiGate routes (YAML)
                            route_data = yaml.safe_load(route_content)
                            route_entries_found = 0
                            for entry in route_data.get('routes', []): # This assumes the FortiGate returns a list of routes under 'routes' key
                                route_entry = RouteEntry(
                                    device_id=device.device_id,
                                    destination_network=entry.get('destination'),
                                    next_hop=entry.get('gateway'),
                                    interface_name=entry.get('interface'),
                                    route_type=entry.get('type')
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
                continue # Continue to process other devices even if one fails

        app_logger.info("Network topology database build process completed.")

    def _find_network_path_in_db(self, source_ip, destination_ip):
        """
        Finds a network path between source and destination IPs using the data
        stored in the PostgreSQL database.
        This replaces the functionality of pathfinder.py.
        """
        app_logger.info(f"Starting pathfinding from {source_ip} to {destination_ip} using DB data.")
        
        path = [] # List of tuples: (device_hostname, outgoing_interface, next_hop_ip, route_type)
        firewalls_in_path = [] # List of firewall hostnames

        try:
            source_ip_obj = ipaddress.ip_address(source_ip)
            destination_ip_obj = ipaddress.ip_address(destination_ip)
        except ipaddress.AddressValueError:
            app_logger.error(f"Invalid IP address format during pathfinding: Source={source_ip}, Destination={destination_ip}")
            return "Error: Invalid IP address format. Please enter valid IPv4 addresses.", []

        # 1. Try to find the device directly connected to the source_ip
        src_device = None
        src_interface = None
        src_network = None

        app_logger.debug(f"Attempting to find source device for IP: {source_ip_obj}")
        
        # Look for the source IP on an interface's exact IPv4 address
        intf_direct_match = Interface.query.filter(
            Interface.ipv4_address == str(source_ip_obj)
        ).first()

        if intf_direct_match:
            src_device = Device.query.get(intf_direct_match.device_id)
            src_interface = intf_direct_match.name
            src_network = intf_direct_match.ipv4_subnet # Get the network from the interface
            app_logger.info(f"Source IP {source_ip_obj} found directly on interface {src_interface} of device {src_device.hostname}.")
        else:
            # If not direct match, try to find the device whose interface's subnet contains the source_ip
            app_logger.debug(f"Source IP {source_ip_obj} not found directly on an interface. Checking subnets.")
            # Fetch all interfaces with defined subnets
            all_interfaces_with_subnets = Interface.query.filter(Interface.ipv4_subnet.isnot(None)).all()
            
            # --- NEW DEBUGGING FOR SUBNET CHECK ---
            app_logger.debug(f"Total interfaces with subnets found in DB: {len(all_interfaces_with_subnets)}")
            # --- END NEW DEBUGGING ---

            for intf in all_interfaces_with_subnets:
                try:
                    # Parse the stored CIDR string to an ip_network object
                    interface_network = ipaddress.ip_network(intf.ipv4_subnet, strict=False)
                    # --- NEW DEBUGGING FOR SUBNET CHECK ---
                    app_logger.debug(f"Checking interface '{intf.name}' (Device ID: {intf.device_id}) on device {Device.query.get(intf.device_id).hostname} with subnet '{intf.ipv4_subnet}'. Is {source_ip_obj} in {interface_network}? {source_ip_obj in interface_network}")
                    # --- END NEW DEBUGGING ---
                    
                    if source_ip_obj in interface_network:
                        src_device = Device.query.get(intf.device_id)
                        src_interface = intf.name
                        src_network = intf.ipv4_subnet
                        app_logger.info(f"Source IP {source_ip_obj} found within subnet {intf.ipv4_subnet} of interface {src_interface} on device {src_device.hostname}.")
                        break
                except ValueError as e:
                    app_logger.warning(f"Error parsing IPv4 subnet '{intf.ipv4_subnet}' for interface {intf.name} (Device ID: {intf.device_id}): {e}")
                    continue

        if not src_device:
            app_logger.warning(f"Source IP {source_ip} not found on any device interface or within any known subnet in the database.")
            return f"Pathfinding failed: Source IP {source_ip} not found on any device interface or within any known subnet.", []

        # Pathfinding now begins from src_device (which has the interface connected to source_ip's network)
        # We start by adding the connection to the source network, not the device itself as the first hop for path.
        path.append({
            'type': 'source_network_entry',
            'ip': str(source_ip_obj),
            'device': src_device.hostname,
            'interface': src_interface,
            'network': src_network
        })
        
        current_ip_on_path = source_ip_obj
        current_device_on_path = src_device
        
        max_hops = 10
        for hop_count in range(max_hops):
            if current_ip_on_path == destination_ip_obj:
                app_logger.info(f"Destination IP {destination_ip_obj} reached.")
                break

            app_logger.debug(f"Hop {hop_count}: Currently on device {current_device_on_path.hostname}, looking for route to {destination_ip_obj}.")

            routes_from_current_device = RouteEntry.query.filter(
                RouteEntry.device_id == current_device_on_path.device_id
            ).order_by(db.func.length(RouteEntry.destination_network).desc()).all()

            next_hop_found_in_routes = False
            for route in routes_from_current_device:
                try:
                    dest_net = ipaddress.ip_network(route.destination_network, strict=False)
                    if destination_ip_obj in dest_net:
                        app_logger.debug(f"Found matching route on {current_device_on_path.hostname}: {route.destination_network} via {route.next_hop or 'direct'} on {route.interface_name}.")
                        
                        path.append({
                            'type': 'route_hop',
                            'device': current_device_on_path.hostname,
                            'destination_network': route.destination_network,
                            'next_hop': route.next_hop,
                            'interface': route.interface_name,
                            'route_type': route.route_type
                        })

                        if route.next_hop:
                            next_hop_ip = ipaddress.ip_address(route.next_hop)
                            next_intf = Interface.query.filter(Interface.ipv4_address == str(next_hop_ip)).first()
                            if next_intf:
                                next_device = Device.query.get(next_intf.device_id)
                                if next_device:
                                    current_device_on_path = next_device
                                    current_ip_on_path = next_hop_ip
                                    next_hop_found_in_routes = True
                                    app_logger.info(f"Path continues to device {current_device_on_path.hostname} via next hop {next_hop_ip}.")
                                    break
                                else:
                                    app_logger.warning(f"Next hop IP {next_hop_ip} on {current_device_on_path.hostname} leads to unknown device. Path may terminate.")
                                    path.append({
                                        'type': 'path_end',
                                        'reason': 'Next hop device unknown',
                                        'ip': str(next_hop_ip)
                                    })
                                    next_hop_found_in_routes = True
                                    current_ip_on_path = destination_ip_obj + 1 # Force exit loop, indicate not reached
                                    break
                            else:
                                app_logger.warning(f"Next hop IP {next_hop_ip} on {current_device_on_path.hostname} not found on any interface. Path may terminate.")
                                path.append({
                                    'type': 'path_end',
                                    'reason': 'Next hop IP not on any interface',
                                    'ip': str(next_hop_ip)
                                })
                                next_hop_found_in_routes = True
                                current_ip_on_path = destination_ip_obj + 1 # Force exit loop, indicate not reached
                                break
                        else:
                            app_logger.info(f"Destination IP {destination_ip_obj} is directly connected to {current_device_on_path.hostname}.")
                            current_ip_on_path = destination_ip_obj
                            next_hop_found_in_routes = True
                            break
                except ipaddress.AddressValueError:
                    app_logger.warning(f"Invalid network format in route entry: {route.destination_network} on device {current_device_on_path.hostname}.")
                    continue

            if not next_hop_found_in_routes:
                app_logger.warning(f"No valid route found from {current_device_on_path.hostname} for destination {destination_ip}.")
                path.append({
                    'type': 'path_end',
                    'reason': 'No route found',
                    'device': current_device_on_path.hostname
                })
                break

            if current_ip_on_path == destination_ip_obj:
                app_logger.info(f"Pathfinding successfully reached destination {destination_ip_obj}.")
                break

        if current_ip_on_path != destination_ip_obj:
            app_logger.warning(f"Pathfinding stopped before reaching destination {destination_ip_obj}. Final IP on path: {current_ip_on_path}")
            return f"Pathfinding failed: Could not reach {destination_ip}.", []

        # Identify firewalls in the path based on 'device' in each hop
        unique_firewall_hostnames = set()
        for hop in path:
            if 'device' in hop:
                device_obj = Device.query.filter_by(hostname=hop['device']).first()
                if device_obj and device_obj.device_type == "Firewall":
                    unique_firewall_hostnames.add(device_obj.hostname)

        firewalls_in_path = list(unique_firewall_hostnames)
        app_logger.info(f"Path found. Firewalls in path: {firewalls_in_path}")
        app_logger.debug(f"Full path trace: {json.dumps(path, indent=2)}")
        return path, firewalls_in_path

    def perform_pre_check(self, rule_data, firewalls_involved):
        """
        Performs pre-checks on relevant firewalls.
        Now also includes internal pathfinding using the DB.
        `firewalls_involved` is the initial list provided by the user/form.
        """
        app_logger.info(f"Performing pre-check for rule {rule_data['rule_id']} on firewalls initially specified: {firewalls_involved}")

        pre_check_stdout = ""
        pre_check_stderr = ""
        
        # Step 1: Run data collection and build internal DB if not recently done
        # TODO: Add a timestamp or flag to avoid frequent collection for performance
        try:
            self.run_data_collection()
        except Exception as e:
            app_logger.error(f"Initial network data collection failed during pre-check: {e}", exc_info=True)
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
        rule_data['firewalls_involved'] = discovered_firewalls 

        firewalls_for_precheck = discovered_firewalls

        if not firewalls_for_precheck:
            app_logger.warning(f"No firewalls identified for pre-check between {rule_data['source_ip']} and {rule_data['destination_ip']} based on current network topology.")
            return "No firewalls in path require pre-check based on current network topology. Skipping pre-checks.", "", [], []

        for firewall_name in firewalls_for_precheck:
            extra_vars = {
                'firewall_name': firewall_name,
                'source_ip': rule_data['source_ip'],
                'destination_ip': rule_data['destination_ip'],
                'protocol': rule_data['protocol'],
                'port': rule_data['ports'][0] if rule_data['ports'] else 'any'
            }

            playbook = None
            if firewall_name.lower().startswith('pa'):
                playbook = 'pre_check_firewall_rule_paloalto.yml'
            elif firewall_name.lower().startswith('fgt'):
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
                    if 'firewalls_already_configured' not in rule_data or rule_data['firewalls_already_configured'] is None:
                        rule_data['firewalls_already_configured'] = []
                    rule_data['firewalls_already_configured'].append(firewall_name)
                else:
                    app_logger.info(f"Rule {rule_data['rule_id']} does NOT exist on {firewall_name}.")
                    if 'firewalls_to_provision' not in rule_data or rule_data['firewalls_to_provision'] is None:
                        rule_data['firewalls_to_provision'] = []
                    rule_data['firewalls_to_provision'].append(firewall_name)

            except RuntimeError as e:
                app_logger.error(f"Failed to pre-check rule {rule_data['rule_id']} on {firewall_name}: {e}")
            except Exception as e:
                app_logger.critical(f"An unexpected error occurred during pre-check for rule {rule_data['rule_id']} on {firewall_name}: {e}")
        
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
                'dest_port': rule_data['ports'][0] if rule_data['ports'] else 'any',
                'rule_description': rule_data['rule_description']
            }

            playbook = None
            if firewall_name.lower().startswith('pa'):
                playbook = 'provision_firewall_rule_paloalto.yml'
            elif firewall_name.lower().startswith('fgt'):
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
                'dest_port': rule_data['ports'][0] if rule_data['ports'] else 'any'
            }

            playbook = None
            if firewall_name.lower().startswith('pa'):
                playbook = 'post_check_firewall_rule_paloalto.yml'
            elif firewall_name.lower().startswith('fgt'):
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

            except RuntimeError as e:
                app_logger.error(f"Failed to post-check rule {rule_data['rule_id']} on {firewall_name}: {e}")
                unverified_firewalls.append(firewall_name)
                post_check_stderr += f"\n--- {firewall_name} ERROR ---\n" + str(e)
            except Exception as e:
                app_logger.critical(f"An unexpected error occurred during post-check for rule {rule_data['rule_id']} on {firewall_name}: {e}")
                unverified_firewalls.append(firewall_name)
                post_check_stderr += f"\n--- {firewall_name} UNEXPECTED ERROR ---\n" + str(e)

        return post_check_stdout, post_check_stderr, verified_firewalls, unverified_firewalls
