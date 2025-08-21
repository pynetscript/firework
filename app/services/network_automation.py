import subprocess
import os
import json
import logging
import yaml
import ipaddress
import re
from sqlalchemy import func
import time
import heapq

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

    @staticmethod
    def _is_default_route(cidr: str) -> bool:
        """
        Check if a given network string is the IPv4 default route 0.0.0.0/0.
        """
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            return (
                net.version == 4 and
                net.prefixlen == 0 and
                int(net.network_address) == 0
            )
        except Exception:
            return False

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
                                    for intf_name, intf_details in interface_data.get('meta', {}).get('results', {}).items():
                                        app_logger.debug(f"Parsing FortiGate interface '{intf_name}' details: {json.dumps(intf_details)}")

                                        ip_address = intf_details.get('ip')
                                        mask_prefix = intf_details.get('mask')

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
                                            mac_address=intf_details.get('mac', '').replace(':', ''),
                                            status='up' if intf_details.get('link') else 'down',
                                            type='Ethernet'
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
                                if hostname.startswith('R') or hostname.startswith('SW'):
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
                                elif hostname == 'pafw':
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
        Finds a network path between source and destination IPs/networks using the data
        stored in the PostgreSQL database.
        This replaces the functionality of pathfinder.py and properly handles CIDR destinations.
        """
        app_logger.info(f"Starting pathfinding from {source_ip} to {destination_ip} using DB data.")

        # 1. Parse Source and Destination IPs
        source_ip_obj = None
        destination_obj = None
        is_destination_network = False
        is_source_network = False # Add a flag for source being a network

        try:
            # Try to parse source as a single IP address first
            source_ip_obj = ipaddress.ip_address(source_ip)
            is_source_network = False
            app_logger.debug(f"Parsed source as IP: {source_ip_obj}")
        except ValueError:
            try:
                # If not a single IP, try to parse as a network (CIDR)
                source_ip_obj = ipaddress.ip_network(source_ip, strict=False)
                is_source_network = True
                app_logger.debug(f"Parsed source as network: {source_ip_obj}")
            except ValueError:
                app_logger.error(f"Invalid source IP address or network format: {source_ip}")
                raise PathfindingError(f"Invalid source IP address or network: {source_ip}")

        try:
            # Try to parse destination as a single IP address first
            destination_obj = ipaddress.ip_address(destination_ip)
            is_destination_network = False
            app_logger.debug(f"Parsed destination as IP: {destination_obj}")
        except ValueError:
            try:
                # If not a single IP, try to parse as a network (CIDR)
                destination_obj = ipaddress.ip_network(destination_ip, strict=False)
                is_destination_network = True
                app_logger.debug(f"Parsed destination as network: {destination_obj}")
            except ValueError:
                app_logger.error(f"Invalid destination IP address or network format: {destination_ip}")
                raise PathfindingError(f"Invalid destination IP address or network: {destination_ip}")

        path = []
        firewalls_in_path = []

        # 2. Build the Graph
        # Nodes in the graph are IP addresses of *managed device interfaces*.
        # Edges represent direct connectivity or next-hop routes.
        graph = {}  # {interface_ip_obj: [(neighbor_ip_obj, cost), ...]}
        device_by_ip = {}  # {interface_ip_obj: device_name}
        interface_by_ip = {} # {interface_ip_obj: interface_name}
        interface_network_map = {} # {interface_ip_obj: ipaddress.ip_network_obj}

        all_device_interfaces = Interface.query.join(Device).all()
        app_logger.debug(f"Found {len(all_device_interfaces)} interfaces in DB.")
        for interface in all_device_interfaces:
            try:
                ip_obj = ipaddress.ip_address(interface.ipv4_address)

                # Create ip_network object for the interface
                if interface.ipv4_subnet:
                    interface_network = ipaddress.ip_network(interface.ipv4_subnet, strict=False)
                else: # Assume /32 if no subnet mask (single host network)
                    interface_network = ipaddress.ip_network(f"{interface.ipv4_address}/32", strict=False)

                device_name = interface.device.hostname
                interface_name = interface.name

                if ip_obj not in graph:
                    graph[ip_obj] = [] # Initialize adjacency list for this node

                device_by_ip[ip_obj] = device_name
                interface_by_ip[ip_obj] = interface_name
                interface_network_map[ip_obj] = interface_network
                app_logger.debug(f"Added interface {interface_name} ({ip_obj}/{interface_network.prefixlen}) on {device_name} to graph nodes.")

            except ValueError:
                app_logger.warning(f"Skipping interface {interface.name} on {interface.device.hostname} due to invalid IP address or subnet mask: {interface.ipv4_address}/{interface.ipv4_subnet}")
                continue
            except Exception as e:
                app_logger.error(f"Unexpected error processing interface {interface.name} on {interface.device.hostname}: {e}")
                continue

        # Add edges based on ARP entries (direct connections) and Route entries (next hops)
        for interface_ip_obj, device_name in device_by_ip.items():
            device = Device.query.filter_by(hostname=device_name).first()
            if not device:
                app_logger.warning(f"Device {device_name} not found in DB for interface IP {interface_ip_obj}. Skipping edge creation for this interface.")
                continue

            # Add edges from ARP entries (direct neighbors on the same segment)
            arp_entries = ArpEntry.query.filter_by(device_id=device.device_id).all()
            app_logger.debug(f"Checking {len(arp_entries)} ARP entries for device {device_name} (interface {interface_ip_obj}).")
            for arp_entry in arp_entries:
                try:
                    arp_ip_obj = ipaddress.ip_address(arp_entry.ip_address)
                    # Check if the ARP entry's IP is within the same network as the current interface
                    if interface_ip_obj in interface_network_map[interface_ip_obj] and arp_ip_obj in interface_network_map[interface_ip_obj]:
                        if arp_ip_obj in graph and arp_ip_obj != interface_ip_obj:
                            if (arp_ip_obj, 1) not in graph[interface_ip_obj]:
                                graph[interface_ip_obj].append((arp_ip_obj, 1))
                                app_logger.debug(f"Added ARP edge: {interface_ip_obj} -> {arp_ip_obj} (Device: {device_by_ip.get(arp_ip_obj, 'Unknown')}) via ARP entry on {device_name}.")
                except ValueError:
                    app_logger.warning(f"Invalid IP in ARP entry {arp_entry.ip_address} on {device_name}. Skipping.")
                    continue

            # Add edges from Route entries (to next-hop managed interfaces)
            route_entries = RouteEntry.query.filter_by(device_id=device.device_id).all()
            app_logger.debug(f"Checking {len(route_entries)} route entries for device {device_name} (interface {interface_ip_obj}).")
            for route_entry in route_entries:
                if route_entry.next_hop:
                    try:
                        next_hop_ip_obj = ipaddress.ip_address(route_entry.next_hop)
                        # If the next hop is an IP of another managed device's interface, add an edge.
                        # This should represent a logical hop through this device to its next-hop interface.
                        if next_hop_ip_obj in graph and next_hop_ip_obj != interface_ip_obj:
                            if (next_hop_ip_obj, 1) not in graph[interface_ip_obj]:
                                graph[interface_ip_obj].append((next_hop_ip_obj, 1))
                                app_logger.debug(f"Added Route edge from {interface_ip_obj} (on {device_name}) to {next_hop_ip_obj} (on {device_by_ip.get(next_hop_ip_obj, 'Unknown')}) via route to {route_entry.destination_network}.")
                        else:
                            app_logger.debug(f"Next hop {next_hop_ip_obj} from route {route_entry.destination_network} on {device_name} is not a managed interface, or is self. Not adding direct edge in graph.")

                    except ValueError:
                        app_logger.warning(f"Invalid next-hop IP in route entry {route_entry.next_hop} on {device_name}. Skipping.")
                        continue
                else:
                    app_logger.debug(f"Route entry to {route_entry.destination_network} on {device_name} has no next-hop, likely directly connected. Not adding explicit next-hop edge.")


        app_logger.info(f"Graph built with {len(graph)} nodes (managed interfaces) and {sum(len(v) for v in graph.values())} edges.")
        if not graph:
            app_logger.error("Graph is empty. No managed devices or interfaces found with valid IPs.")
            raise PathfindingError("No network topology data available. Graph is empty.")

        # 3. Dijkstra's Algorithm
        distances = {ip: float('inf') for ip in graph}
        predecessors = {ip: None for ip in graph}
        priority_queue = [] # (distance, ip_obj)

        # Determine the best starting point
        start_node = None
        app_logger.debug(f"Attempting to find start node for source: {source_ip_obj} (Is network: {is_source_network})")
        for interface_ip_obj, interface_network in interface_network_map.items():
            app_logger.debug(f"Checking interface: {interface_ip_obj} (Network: {interface_network}) on device {device_by_ip.get(interface_ip_obj)}")
            source_matches_interface = False
            if is_source_network:
                # If source is a network, check if it overlaps with or is a subnet of the interface's network
                overlaps = source_ip_obj.overlaps(interface_network)
                subnet_of_src = source_ip_obj.subnet_of(interface_network) # Is source_ip_obj a subnet of interface_network?
                subnet_of_if = interface_network.subnet_of(source_ip_obj) # Is interface_network a subnet of source_ip_obj?

                source_matches_interface = overlaps or subnet_of_src or subnet_of_if
                app_logger.debug(f"  Network comparison: overlaps={overlaps}, subnet_of_src={subnet_of_src}, subnet_of_if={subnet_of_if}. Result: {source_matches_interface}")
            else:
                # If source is a single IP, check if it's within the interface's network
                source_matches_interface = source_ip_obj in interface_network
                app_logger.debug(f"  IP in network comparison: {source_ip_obj} in {interface_network}. Result: {source_matches_interface}")

            if source_matches_interface:
                start_node = interface_ip_obj
                distances[start_node] = 0
                heapq.heappush(priority_queue, (0, start_node))
                app_logger.info(f"Initial pathfinding start node: {start_node} on device {device_by_ip.get(start_node)} (Source {source_ip} is in/overlaps with its network {interface_network}).")
                break # Found a directly connected starting point

        if start_node is None:
            app_logger.error(f"Source {source_ip} is not directly connected to or does not overlap with any managed device's interface network. Pathfinding cannot begin.")
            raise DestinationUnreachableError(f"Source {source_ip} is not directly connected to or does not overlap with any managed device's interface network. Pathfinding cannot begin.")

        # Store the final node in the graph that reaches the destination (if not the destination_obj itself)
        final_reachable_node = None
        destination_found_via_route = False # This flag indicates if the path *ends* because a device has a route to unmanaged space/final destination

        while priority_queue:
            current_distance, current_ip_obj = heapq.heappop(priority_queue)

            if current_distance > distances[current_ip_obj]:
                app_logger.debug(f"Skipping {current_ip_obj}: already found shorter path.")
                continue

            app_logger.debug(f"Exploring from {current_ip_obj} (Device: {device_by_ip.get(current_ip_obj, 'Unknown')}, Distance: {current_distance})")

            # Check if destination reached (either directly or via a route from current device)
            destination_reached_in_loop = False

            # Case 1: Current node IS the destination (or within the destination network if it's a subnet)
            if (not is_destination_network and current_ip_obj == destination_obj) or \
               (is_destination_network and current_ip_obj in destination_obj):
                destination_reached_in_loop = True
                final_reachable_node = current_ip_obj
                app_logger.info(f"Direct destination match: {destination_ip} reached via interface {current_ip_obj} on {device_by_ip.get(current_ip_obj)}.")

            # Case 2: Current device has a route to the destination
            if not destination_reached_in_loop: # Only check routes if not already directly at destination
                current_device_name = device_by_ip.get(current_ip_obj)
                if current_device_name:
                    current_device = Device.query.filter_by(hostname=current_device_name).first()
                    if current_device:
                        relevant_routes = RouteEntry.query.filter_by(device_id=current_device.device_id).all()
                        app_logger.debug(f"Checking {len(relevant_routes)} routes on device {current_device_name} for destination {destination_ip}.")

                        for route_entry in relevant_routes:
                            try:
                                route_dest_network = ipaddress.ip_network(route_entry.destination_network, strict=False)
                                target_matched = False
                                if is_destination_network:
                                    target_matched = destination_obj.overlaps(route_dest_network) or destination_obj.subnet_of(route_dest_network) or route_dest_network.subnet_of(destination_obj)
                                else: # Destination is a single IP address
                                    target_matched = destination_obj in route_dest_network

                                if target_matched:
                                    # --- START OF CRITICAL LOGIC ADJUSTMENT ---
                                    # If the route has a next hop, and that next hop is a managed interface,
                                    # then this is NOT the end of the path. We should try to continue.
                                    next_hop_ip_obj = None
                                    if route_entry.next_hop:
                                        try:
                                            next_hop_ip_obj = ipaddress.ip_address(route_entry.next_hop)
                                        except ValueError:
                                            app_logger.debug(f"Route {route_entry.destination_network} on {current_device_name} has invalid next hop IP {route_entry.next_hop}. Treating as unmanaged.")

                                    if next_hop_ip_obj and next_hop_ip_obj in graph:
                                        # This means the next hop is a managed device interface.
                                        # We should NOT mark destination_reached_in_loop as True here.
                                        # Instead, this route should have created an edge in graph construction,
                                        # and Dijkstra's will naturally explore it.
                                        app_logger.debug(f"Route {route_entry.destination_network} on {current_device_name} points to managed next hop {next_hop_ip_obj}. Path will continue.")
                                        # Do nothing further in this `if target_matched` block
                                        # The path will continue via the edge added earlier in graph building.
                                    else:
                                        # This is the point where the path leaves our managed network,
                                        # or reaches the destination if it's directly connected via this route.
                                        if self._is_default_route(route_entry.destination_network):
                                            msg = (f"Destination {destination_ip} is only reachable via default route ({route_entry.destination_network}.")
                                            app_logger.warning(msg)
                                            raise DestinationUnreachableError(msg)
                                        destination_reached_in_loop = True
                                        final_reachable_node = current_ip_obj # The path effectively ends here as this device knows the way
                                        destination_found_via_route = True
                                        app_logger.info(f"Destination {destination_ip} reached via route {route_entry.destination_network} on device {current_device_name} (interface {current_ip_obj}). Next hop is unmanaged or direct: {route_entry.next_hop if route_entry.next_hop else 'directly connected'}.")
                                        break # Found a matching route that exits managed network, no need to check other routes on this device
                                    # --- END OF CRITICAL LOGIC ADJUSTMENT ---
                            except ValueError:
                                app_logger.warning(f"Error parsing route network '{route_entry.destination_network}' for device {current_device_name}. Skipping route.")
                                continue
                else:
                    app_logger.debug(f"Current IP {current_ip_obj} has no associated device name. Cannot check routes.")

            if destination_reached_in_loop:
                app_logger.info(f"Pathfinding completed: Destination {destination_ip} reached.")
                break # Path found, exit Dijkstra's loop

            # Explore neighbors
            for neighbor_ip_obj, edge_cost in graph.get(current_ip_obj, []):
                distance = current_distance + edge_cost
                if distance < distances[neighbor_ip_obj]:
                    distances[neighbor_ip_obj] = distance
                    predecessors[neighbor_ip_obj] = current_ip_obj
                    heapq.heappush(priority_queue, (distance, neighbor_ip_obj))
                    app_logger.debug(f"Updating path: {current_ip_obj} -> {neighbor_ip_obj} (on {device_by_ip.get(neighbor_ip_obj, 'Unknown')}) with new distance {distance}.")
                else:
                    app_logger.debug(f"Not updating path to {neighbor_ip_obj} from {current_ip_obj}: current distance {distance} is not shorter than existing {distances[neighbor_ip_obj]}.")

        # 4. Path Reconstruction
        if final_reachable_node is None:
            app_logger.error(f"Pathfinding stopped, but no path was found to destination {destination_ip}. Final reachable node is None.")
            raise DestinationUnreachableError(f"Pathfinding failed: Could not reach {destination_ip}. Destination unreachable from managed network.")

        app_logger.info(f"Path found to {destination_ip}. Reconstructing path from {final_reachable_node}...")
        current = final_reachable_node
        path_segments = []

        # Add the final destination details if it was an explicit IP/network reached by a route
        if not destination_found_via_route: # If the final_reachable_node itself was the destination
             path_segments.append({
                'type': 'destination_reached_directly',
                'ip': str(current),
                'device': device_by_ip.get(current),
                'interface': interface_by_ip.get(current),
                'note': f"Directly reached destination IP/network {destination_ip}"
            })
        else: # Reached via a route, ending at 'current' managed device
            current_device_name = device_by_ip.get(current)
            current_device = Device.query.filter_by(hostname=current_device_name).first()
            if current_device:
                # Find the specific route that led to the destination
                final_route_found_details = None
                relevant_routes_at_end = RouteEntry.query.filter_by(device_id=current_device.device_id).all()
                for route_entry in relevant_routes_at_end:
                    try:
                        route_dest_network = ipaddress.ip_network(route_entry.destination_network, strict=False)
                        target_matched = False
                        if is_destination_network:
                            target_matched = destination_obj.overlaps(route_dest_network) or destination_obj.subnet_of(route_dest_network) or route_dest_network.subnet_of(destination_obj)
                        else:
                            target_matched = destination_obj in route_dest_network

                        # Re-evaluate the next_hop in reconstruction, similar to Dijkstra's loop
                        next_hop_ip_obj = None
                        if route_entry.next_hop:
                            try:
                                next_hop_ip_obj = ipaddress.ip_address(route_entry.next_hop)
                            except ValueError:
                                pass # Invalid IP, treat as unmanaged

                        # This route is relevant only if it covers the destination AND
                        # its next-hop is NOT another managed interface (because if it were,
                        # Dijkstra would have continued).
                        if target_matched and (not next_hop_ip_obj or next_hop_ip_obj not in graph):
                            final_route_found_details = {
                                'type': 'route_hop',
                                'device': current_device.hostname,
                                'source_interface_on_device': interface_by_ip.get(current),
                                'destination_network': route_entry.destination_network,
                                'next_hop': route_entry.next_hop if route_entry.next_hop else "directly connected",
                                'interface_out': route_entry.interface_name,
                                'route_type': route_entry.route_type,
                                'reached_final_destination': True
                            }
                            app_logger.debug(f"Identified final route leading to destination: {route_entry.destination_network} via {route_entry.next_hop} on {current_device.hostname}.")
                            break
                    except ValueError:
                        app_logger.warning(f"Error parsing route {route_entry.destination_network} during final path reconstruction on {current_device.hostname}.")
                        continue
                if final_route_found_details:
                    path_segments.append(final_route_found_details)
                else:
                    app_logger.warning(f"Final reachable node {current} on device {current_device.hostname} knew about the destination {destination_ip} but couldn't pinpoint the exact route during reconstruction, or it was an intermediate hop that should have led to another managed device.")
                    path_segments.append({
                        'type': 'final_managed_device_route_known',
                        'device': current_device.hostname,
                        'interface': interface_by_ip.get(current),
                        'ip': str(current),
                        'note': f"Path ended here, device {current_device.hostname} knows route to {destination_ip}, but specific route details not captured for final hop or it was an intermediate hop."
                    })
            else:
                app_logger.warning(f"Final reachable node {current} has no associated device during path reconstruction. Path might be incomplete.")

        # Traverse back from the final_reachable_node to the start_node
        while current and predecessors.get(current) is not None:
            prev = predecessors[current]
            app_logger.debug(f"Reconstructing path: current={current} (device={device_by_ip.get(current)}), prev={prev} (device={device_by_ip.get(prev)})")

            if device_by_ip.get(current) != device_by_ip.get(prev):
                path_segments.append({
                    'type': 'device_hop',
                    'from_device': device_by_ip.get(prev),
                    'from_interface_ip': str(prev),
                    'to_device': device_by_ip.get(current),
                    'to_interface_ip': str(current),
                    'next_hop_type': 'inter-device'
                })
            else:
                path_segments.append({
                    'type': 'internal_hop_between_interfaces', # Renamed for clarity
                    'device': device_by_ip.get(current),
                    'from_interface_ip': str(prev),
                    'to_interface_ip': str(current),
                    'note': 'This hop indicates traffic moved between two interfaces on the same device to reach a managed interface closer to the destination.'
                })
            current = prev

        # Add the initial source network entry
        if start_node:
            path_segments.append({
                'type': 'source_network_entry',
                'ip': str(source_ip_obj),
                'device': device_by_ip.get(start_node),
                'interface': interface_by_ip.get(start_node),
                'network': str(interface_network_map.get(start_node)),
                'note': 'Origin of traffic within the managed network.'
            })
        else:
            app_logger.warning("Start node was None during path reconstruction, cannot add source network entry details fully.")
            path_segments.append({
                'type': 'source_network_entry_unresolved',
                'ip': str(source_ip_obj),
                'note': 'Starting point within the managed network could not be fully resolved to a specific interface/device.'
            })

        path.extend(reversed(path_segments)) # Reverse to get path from source to destination

        # 5. Identify Firewalls in Path
        unique_firewall_hostnames = set()
        for hop in path:
            device_name_in_hop = None
            if 'device' in hop:
                device_name_in_hop = hop['device']
            elif 'from_device' in hop: # For device_hop types
                device_name_in_hop = hop['from_device']

            if device_name_in_hop and device_name_in_hop != "Unknown (initial check)":
                device_obj = Device.query.filter_by(hostname=device_name_in_hop).first()
                if device_obj and device_obj.device_type == "Firewall":
                    unique_firewall_hostnames.add(device_obj.hostname)

        firewalls_in_path = list(unique_firewall_hostnames)
        app_logger.info(f"Path found. Firewalls identified in path: {firewalls_in_path}")
        app_logger.debug(f"Full path trace: {json.dumps(path, indent=2)}")

        return path, firewalls_in_path

    def perform_pre_check(self, rule_data, firewalls_involved):
        """
        Performs pre-checks on relevant firewalls.
        """
        app_logger.info(f"Performing pre-check for rule {rule_data['rule_id']} on involved firewalls: {firewalls_involved}")

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
                else:
                    raise PathfindingError(f"Pathfinding failed: {path}")

            app_logger.info(f"Pathfinding completed. Discovered firewalls in path: {discovered_firewalls}")
            rule_data['firewalls_involved'] = discovered_firewalls

        except (DestinationUnreachableError, PathfindingError) as e:
            app_logger.error(f"Pathfinding pre-check failed for rule {rule_data['rule_id']}: {e}")
            raise e
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
