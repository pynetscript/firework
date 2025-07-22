import subprocess
import os
import json
import logging
import yaml
import ipaddress
import re
from sqlalchemy import func
import time

from app.models import db, Device, Interface, ArpEntry, RouteEntry

app_logger = logging.getLogger(__name__)

class PathfindingError(Exception):
    """Custom exception for general pathfinding failures."""
    pass

class DestinationUnreachableError(PathfindingError):
    """Custom exception for when the destination is specifically unreachable."""
    pass

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

        self.vault_password_file = os.getenv('FIREWORK_VAULT_PASS_FILE')
        if self.vault_password_file:
            if not os.path.exists(self.vault_password_file):
                app_logger.warning(f"Vault password file specified in environment ({self.vault_password_file}) not found.")
            else:
                app_logger.info(f"Using vault password file from environment: {self.vault_password_file}")
        else:
            app_logger.info("FIREWORK_VAULT_PASS_FILE environment variable not set. Ansible commands requiring vault might fail.")

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

        if self.vault_password_file:
            command.extend(['--vault-password-file', self.vault_password_file])
            app_logger.debug(f"Adding --vault-password-file {self.vault_password_file} to command.")

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
            # Exclude FIREWORK_VAULT_PASS_FILE from verbose logging if sensitive
            if k in ['PATH', 'USER', 'HOME', 'ANSIBLE_CACHE_DIR', 'ANSIBLE_TMPDIR', 'TMPDIR', 'ANSIBLE_COLLECTIONS_PATH', 'ANSIBLE_HOST_KEY_CHECKING', 'FIREWORK_VAULT_PASS_FILE']:
                 # Mask sensitive path for logging
                if k == 'FIREWORK_VAULT_PASS_FILE':
                    app_logger.debug(f"  {k}=<masked_path_to_vault_file>")
                else:
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
        """
        app_logger.info("Starting network topology database build process in PostgreSQL.")

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
            elif '_arp.txt' in filename or '_arp.yml' in filename:
                file_category = 'arp'
            elif '_routes.txt' in filename or '_routes.yml' in filename:
                file_category = 'routes'

            if file_category:
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

                if hostname:
                    if hostname not in device_files:
                        device_files[hostname] = {'type': device_type, 'interfaces': None, 'arp': None, 'routes': None}
                    device_files[hostname][file_category] = filepath
                    app_logger.debug(f"Identified file: {filename} -> Hostname: {hostname}, Category: {file_category}")
                else:
                    app_logger.warning(f"File {filename} matched a category but its hostname pattern was not recognized. Skipping.")
            else:
                app_logger.debug(f"File {filename} did not match any known file category. Skipping.")

        app_logger.info(f"Discovered device files for processing: {json.dumps(device_files, indent=2)}")

        for hostname, files_info in device_files.items():
            app_logger.info(f"Attempting to process data for device: {hostname}")
            try:
                device = Device.query.filter_by(hostname=hostname).first()
                if not device:
                    device = Device(hostname=hostname, device_type=files_info['type'])
                    db.session.add(device)
                    db.session.flush() # Flush to get device.device_id for related objects
                    app_logger.info(f"Added new device '{hostname}' (ID: {device.device_id}) to session.")
                else:
                    app_logger.info(f"Device '{hostname}' (ID: {device.device_id}) already exists in DB.")

                # Process Interfaces
                if files_info.get('interfaces') and os.path.exists(files_info['interfaces']):
                    app_logger.info(f"Processing interfaces for {hostname} from {files_info['interfaces']}")

                    time.sleep(0.1) # Small delay to ensure file is written
                    file_size = os.path.getsize(files_info['interfaces'])
                    app_logger.debug(f"File '{files_info['interfaces']}' size: {file_size} bytes.")
                    if file_size == 0:
                        app_logger.warning(f"Skipping empty interface file for {hostname}: {files_info['interfaces']}")
                    else:
                        try:
                            # Use 'utf-8-sig' to handle Byte Order Mark (BOM) if present
                            with open(files_info['interfaces'], 'r', encoding='utf-8-sig') as f:
                                content = f.read().strip() # Read and strip whitespace/BOM
                                app_logger.debug(f"Raw content of {files_info['interfaces']}:\n{content[:500]}...") # Log first 500 chars

                                if hostname == 'pafw':
                                    interface_data = yaml.safe_load(content)
                                elif hostname == 'fgt':
                                    interface_data = yaml.safe_load(content)
                                else:
                                    interface_data = yaml.safe_load(content)
                                app_logger.debug(f"Parsed interface data for {hostname}: {json.dumps(interface_data, indent=2)}")

                                # --- Process Cisco Interfaces
                                if hostname.startswith('R') or hostname.startswith('SW'):
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

                                # --- Process Palo Alto Interfaces
                                elif hostname == 'pafw':
                                    interfaces_found = 0
                                    for intf_details in interface_data.get('ansible_facts', {}).get('ansible_net_interfaces', []):
                                        app_logger.debug(f"Parsing Palo Alto interface '{intf_details.get('name')}' details: {json.dumps(intf_details)}")

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
                                                mac_address=intf_details.get('mac'),
                                                status=intf_details.get('state'),
                                                type='Ethernet'
                                            )
                                            db.session.add(interface)
                                            interfaces_found += 1
                                            app_logger.info(f"Added interface '{intf_details.get('name')}' ({full_ip_cidr}) for {hostname} to session.")
                                    app_logger.info(f"Finished adding {interfaces_found} interfaces for {hostname}.")

                                # --- Process FGT Interfaces
                                elif hostname == 'fgt':
                                    interfaces_found = 0
                                    # The interface data for FGT is directly under 'meta.results' and then by interface name
                                    for intf_name, intf_details in interface_data.get('meta', {}).get('results', {}).items():
                                        app_logger.debug(f"Parsing FortiGate interface '{intf_name}' details: {json.dumps(intf_details)}")

                                        ip_address = intf_details.get('ip')
                                        mask_prefix = intf_details.get('mask') # This is the mask length, e.g., 24

                                        ipv4_subnet_cidr = None
                                        if ip_address and mask_prefix is not None:
                                            try:
                                                # Construct full CIDR from IP and mask length
                                                network_obj = ipaddress.ip_network(f"{ip_address}/{mask_prefix}", strict=False)
                                                ipv4_subnet_cidr = str(network_obj)
                                                app_logger.debug(f"Constructed CIDR for FGT interface {intf_name}: {ipv4_subnet_cidr}")
                                            except ValueError:
                                                app_logger.warning(f"Invalid FGT IP/mask for {intf_name}: {ip_address}/{mask_prefix}")

                                        interface = Interface(
                                            device_id=device.device_id,
                                            name=intf_name, # Use intf_name (e.g., 'port1')
                                            ipv4_address=ip_address,
                                            ipv4_subnet=ipv4_subnet_cidr,
                                            mac_address=intf_details.get('mac', '').replace(':', ''), # Remove colons for consistency
                                            status='up' if intf_details.get('link') else 'down', # Use 'link' status
                                            type='Ethernet' # Or intf_details.get('type') if available and more specific
                                        )
                                        db.session.add(interface)
                                        interfaces_found += 1
                                        app_logger.info(f"Added interface '{intf_name}' ({ip_address}/{mask_prefix}) for {hostname} to session.")
                                    app_logger.info(f"Finished adding {interfaces_found} interfaces for {hostname}.")

                        except json.JSONDecodeError as e:
                            app_logger.error(f"JSONDecodeError when processing interfaces for {hostname} from {files_info['interfaces']}: {e}", exc_info=True)
                            app_logger.error(f"Content that caused JSONDecodeError (first 500 chars):\n{content[:500]}...")
                        except yaml.YAMLError as e:
                            app_logger.error(f"YAMLError when processing interfaces for {hostname} from {files_info['interfaces']}: {e}", exc_info=True)
                            app_logger.error(f"Content that caused YAMLError (first 500 chars):\n{content[:500]}...")
                        except UnicodeDecodeError as e:
                            app_logger.error(f"UnicodeDecodeError when reading interfaces file for {hostname} from {files_info['interfaces']}: {e}", exc_info=True)
                        except Exception as e:
                            app_logger.error(f"Unexpected error when processing interfaces for {hostname} from {files_info['interfaces']}: {e}", exc_info=True)


                # --- Process ARP entries
                if files_info.get('arp') and os.path.exists(files_info['arp']):
                    app_logger.info(f"Processing ARP for {hostname} from {files_info['arp']}")

                    time.sleep(0.1)
                    file_size = os.path.getsize(files_info['arp'])
                    app_logger.debug(f"File '{files_info['arp']}' size: {file_size} bytes.")
                    if file_size == 0:
                        app_logger.warning(f"Skipping empty ARP file for {hostname}: {files_info['arp']}")
                    else:
                        try:
                            with open(files_info['arp'], 'r', encoding='utf-8-sig') as f:
                                arp_content = f.read().strip()
                                app_logger.debug(f"Raw ARP data for {hostname}:\n{arp_content[:500]}...")
                                arp_entries_found = 0

                                # --- Proccess Cisco ARP
                                if hostname.startswith('R') or hostname.startswith('SW'): # Cisco IOS 'show ip arp' output
                                    for line in arp_content.splitlines():
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

                                # --- Proccess Palo Alto ARP
                                elif hostname == 'pafw': # Palo Alto ARP (JSON output)
                                    arp_data = json.loads(arp_content)
                                    for entry in arp_data.get('response', {}).get('result', {}).get('entries', {}).get('entry', []):
                                        ip = entry.get('ip')
                                        mac = entry.get('mac')
                                        interface = entry.get('interface')
                                        if ip and mac:
                                            arp_entry = ArpEntry(
                                                device_id=device.device_id,
                                                ip_address=ip,
                                                mac_address=mac.replace(':', ''),
                                                interface_name=interface
                                            )
                                            db.session.add(arp_entry)
                                            arp_entries_found += 1
                                            app_logger.info(f"Added PA ARP entry {ip} ({mac}) on {hostname} to session.")
                                    app_logger.info(f"Finished adding {arp_entries_found} ARP entries for {hostname}.")

                                # --- Proccess FGT ARP
                                elif hostname == 'fgt':
                                    arp_data = yaml.safe_load(arp_content)
                                    arp_entries_found = 0
                                    # FGT ARP entries are under meta.results
                                    for entry in arp_data.get('meta', {}).get('results', []):
                                        ip = entry.get('ip')
                                        mac = entry.get('mac')
                                        interface = entry.get('interface')
                                        if ip and mac:
                                            arp_entry = ArpEntry(
                                                device_id=device.device_id,
                                                ip_address=ip,
                                                mac_address=mac.replace(':', ''), # Remove colons
                                                interface_name=interface
                                            )
                                            db.session.add(arp_entry)
                                            arp_entries_found += 1
                                            app_logger.info(f"Added FGT ARP entry {ip} ({mac}) on {hostname} to session.")
                                    app_logger.info(f"Finished adding {arp_entries_found} ARP entries for {hostname}.")

                        except json.JSONDecodeError as e:
                            app_logger.error(f"JSONDecodeError when processing ARP for {hostname} from {files_info['arp']}: {e}", exc_info=True)
                            app_logger.error(f"Content that caused JSONDecodeError (first 500 chars):\n{arp_content[:500]}...")
                        except yaml.YAMLError as e:
                            app_logger.error(f"YAMLError when processing ARP for {hostname} from {files_info['arp']}: {e}", exc_info=True)
                            app_logger.error(f"Content that caused YAMLError (first 500 chars):\n{arp_content[:500]}...")
                        except UnicodeDecodeError as e:
                            app_logger.error(f"UnicodeDecodeError when reading ARP file for {hostname} from {files_info['arp']}: {e}", exc_info=True)
                        except Exception as e:
                            app_logger.error(f"Unexpected error when processing ARP for {hostname} from {files_info['arp']}: {e}", exc_info=True)

                # Process Route entries
                if files_info.get('routes') and os.path.exists(files_info['routes']):
                    app_logger.info(f"Processing routes for {hostname} from {files_info['routes']}")

                    time.sleep(0.1)
                    file_size = os.path.getsize(files_info['routes'])
                    app_logger.debug(f"File '{files_info['routes']}' size: {file_size} bytes.")
                    if file_size == 0:
                        app_logger.warning(f"Skipping empty route file for {hostname}: {files_info['routes']}")
                    else:
                        try:
                            with open(files_info['routes'], 'r', encoding='utf-8-sig') as f:
                                route_content = f.read().strip()
                                app_logger.debug(f"Raw Route data for {hostname}:\n{route_content[:500]}...")
                                routes_found = 0

                                # --- Process Cisco Routes
                                if hostname.startswith('R') or hostname.startswith('SW'):
                                    for line in route_content.splitlines():
                                        match = re.match(r'^(?:[CDLSRI]\*?|O|E[12]|N[12]|P|i|X|H|a|b|%+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})(?: \[(\d+)\/(\d+)\])?(?: via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?,?\s*(.+)?', line.strip())
                                        if match:
                                            network = match.group(1)
                                            admin_distance = match.group(2)
                                            metric = match.group(3)
                                            next_hop = match.group(4)
                                            interface_name_raw = match.group(5)

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
                                                metric=int(metric) if metric else None,
                                                admin_distance=int(admin_distance) if admin_distance else None,
                                                interface_name=interface_name_raw.strip() if interface_name_raw else None,
                                                route_type=route_type,
                                                flags=line.strip().split(' ')[0]
                                            )
                                            db.session.add(route_entry)
                                            routes_found += 1
                                            app_logger.info(f"Added route {network} via {next_hop} on {hostname} to session.")
                                    app_logger.info(f"Finished adding {routes_found} route entries for {hostname}.")

                                # --- Process Palo Alto Routes
                                elif hostname == 'pafw':
                                    route_data = json.loads(route_content)
                                    for entry in route_data.get('response', {}).get('result', {}).get('entry', []):
                                        destination = entry.get('destination')
                                        next_hop = entry.get('nexthop')
                                        interface = entry.get('interface')
                                        flags = entry.get('flags', '')

                                        readable_route_type = 'unknown'
                                        if 'C' in flags: readable_route_type = 'connected'
                                        elif 'S' in flags: readable_route_type = 'static'
                                        elif 'O' in flags: readable_route_type = 'ospf'
                                        elif 'B' in flags: readable_route_type = 'bgp'
                                        elif 'R' in flags: readable_route_type = 'rip'

                                        if destination:
                                            route_entry = RouteEntry(
                                                device_id=device.device_id,
                                                destination_network=destination,
                                                next_hop=next_hop if next_hop != '0.0.0.0' else None,
                                                interface_name=interface,
                                                route_type=readable_route_type,
                                                flags=flags
                                            )
                                            db.session.add(route_entry)
                                            routes_found += 1
                                            app_logger.info(f"Added PA route {destination} via {next_hop} on {hostname} to session.")
                                    app_logger.info(f"Finished adding {routes_found} route entries for {hostname}.")

                                # --- Process FGT Routes
                                elif hostname == 'fgt':
                                    route_data = yaml.safe_load(route_content)
                                    routes_found = 0
                                    for entry in route_data.get('meta', {}).get('results', []):
                                        destination = entry.get('ip_mask')
                                        gateway = entry.get('gateway')
                                        next_hop = gateway if gateway and gateway != '0.0.0.0' else None

                                        metric = entry.get('metric')
                                        ad_distance = entry.get('distance')
                                        interface_name = entry.get('interface')
                                        route_type = entry.get('type') # 'connect', 'ospf', 'static'

                                        if destination:
                                            route_entry = RouteEntry(
                                                device_id=device.device_id,
                                                destination_network=destination,
                                                next_hop=next_hop,
                                                metric=metric,
                                                admin_distance=ad_distance,
                                                interface_name=interface_name,
                                                route_type=route_type,
                                                flags=entry.get('origin', '')
                                            )
                                            db.session.add(route_entry)
                                            routes_found += 1
                                            app_logger.info(f"Added FGT route {destination} via {next_hop} on {hostname} to session.")
                                    app_logger.info(f"Finished adding {routes_found} routes for {hostname}.")

                        except json.JSONDecodeError as e:
                            app_logger.error(f"JSONDecodeError when processing routes for {hostname} from {files_info['routes']}: {e}", exc_info=True)
                            app_logger.error(f"Content that caused JSONDecodeError (first 500 chars):\n{route_content[:500]}...")
                        except yaml.YAMLError as e:
                            app_logger.error(f"YAMLError when processing routes for {hostname} from {files_info['routes']}: {e}", exc_info=True)
                            app_logger.error(f"Content that caused YAMLError (first 500 chars):\n{route_content[:500]}...")
                        except UnicodeDecodeError as e:
                            app_logger.error(f"UnicodeDecodeError when reading routes file for {hostname} from {files_info['routes']}: {e}", exc_info=True)
                        except Exception as e:
                            app_logger.error(f"Unexpected error when processing routes for {hostname} from {files_info['routes']}: {e}", exc_info=True)

                db.session.commit()
                app_logger.info(f"Successfully committed data for device: {hostname}")

            except Exception as e:
                db.session.rollback()
                app_logger.error(f"Error processing data for device {hostname}: {e}", exc_info=True)
                # Re-raise to indicate failure to the caller (run_data_collection)
                raise RuntimeError(f"Failed to process and store data for device {hostname}: {e}")

        app_logger.info("Network topology database build process completed.")

    def _find_network_path_in_db(self, source_ip, destination_ip):
        """
        Finds a network path between source and destination IPs using the data
        stored in the PostgreSQL database.
        This replaces the functionality of pathfinder.py.
        """
        app_logger.info(f"Starting pathfinding from {source_ip} to {destination_ip} using DB data.")

        path = []
        firewalls_in_path = []

        try:
            source_ip_obj = ipaddress.ip_address(source_ip)
            destination_ip_obj = ipaddress.ip_address(destination_ip)
        except ipaddress.AddressValueError:
            app_logger.error(f"Invalid IP address format during pathfinding: Source={source_ip}, Destination={destination_ip}")
            return "Error: Invalid IP address format. Please enter valid IPv4 addresses.", []

        src_device = None
        src_interface = None
        src_network = None

        app_logger.debug(f"Attempting to find source device for IP: {source_ip_obj}")

        intf_direct_match = Interface.query.filter(
            Interface.ipv4_address == str(source_ip_obj)
        ).first()

        if intf_direct_match:
            src_device = Device.query.get(intf_direct_match.device_id)
            src_interface = intf_direct_match.name
            src_network = intf_direct_match.ipv4_subnet
            app_logger.info(f"Source IP {source_ip_obj} found directly on interface {src_interface} of device {src_device.hostname}.")
        else:
            app_logger.debug(f"Source IP {source_ip_obj} not found directly on an interface. Checking subnets.")
            all_interfaces_with_subnets = Interface.query.filter(Interface.ipv4_subnet.isnot(None)).all()

            app_logger.debug(f"Total interfaces with subnets found in DB: {len(all_interfaces_with_subnets)}")

            for intf in all_interfaces_with_subnets:
                try:
                    interface_network = ipaddress.ip_network(intf.ipv4_subnet, strict=False)
                    app_logger.debug(f"Checking interface '{intf.name}' (Device ID: {intf.device_id}) on device {Device.query.get(intf.device_id).hostname} with subnet '{intf.ipv4_subnet}'. Is {source_ip_obj} in {interface_network}? {source_ip_obj in interface_network}")

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

        discovered_firewalls = []

        try:
            self.run_data_collection()
        except Exception as e:
            app_logger.error(f"Initial network data collection failed during pre-check: {e}", exc_info=True)
            raise RuntimeError(f"Pre-check failed: Network data collection failed. {e}")

        try:
            app_logger.info(f"Performing pathfinding from {rule_data['source_ip']} to {rule_data['destination_ip']}.")
            path, discovered_firewalls = self._find_network_path_in_db(
                rule_data['source_ip'], rule_data['destination_ip']
            )

            if isinstance(path, str):
                app_logger.error(f"Pathfinding failed: {path}")
                if "Could not reach" in path:
                    raise DestinationUnreachableError(f"Destination route was not found for {rule_data['destination_ip']}.")
                else: # For any other pathfinding failure messages
                    raise PathfindingError(f"Pathfinding failed: {path}")

            app_logger.info(f"Pathfinding completed. Discovered firewalls in path: {discovered_firewalls}")
            rule_data['firewalls_involved'] = discovered_firewalls

        except (DestinationUnreachableError, PathfindingError) as e:
            app_logger.error(f"Pathfinding pre-check failed for rule {rule_data['rule_id']}: {e}")
            raise e # This ensures the custom exception is propagated
        except Exception as e:
            app_logger.critical(f"An unexpected error occurred during pathfinding for rule {rule_data['rule_id']}: {e}", exc_info=True)
            raise RuntimeError(f"An unexpected error occurred during network pre-check (pathfinding): {e}")

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

        return pre_check_stdout, pre_check_stderr, firewalls_for_precheck, rule_data.get('firewalls_already_configured', [])


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

                if "POLICY_VERIFIED" in stdout:
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
