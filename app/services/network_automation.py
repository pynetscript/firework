import subprocess
import os
import json
import sys
import sqlite3 # Import sqlite3 to query device types from DB
import logging # Import logging

# Get a logger for this service
app_logger = logging.getLogger(__name__)

# Define paths to your scripts and inventory relative to the project root
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
ANSIBLE_INVENTORY = os.path.join(PROJECT_ROOT, 'inventory.yml')
ANSIBLE_COLLECTOR_PLAYBOOK = os.path.join(PROJECT_ROOT, 'collector.yml')
DB_BUILDER_SCRIPT = os.path.join(PROJECT_ROOT, 'build_db.py')
PATHFINDER_SCRIPT = os.path.join(PROJECT_ROOT, 'pathfinder.py')

# New device-specific playbooks
ANSIBLE_PROVISION_PALOALTO_PLAYBOOK = os.path.join(PROJECT_ROOT, 'provision_firewall_rule_paloalto.yml')
ANSIBLE_PROVISION_FORTINET_PLAYBOOK = os.path.join(PROJECT_ROOT, 'provision_firewall_rule_fortinet.yml')

ANSIBLE_POST_CHECK_PALOALTO_PLAYBOOK = os.path.join(PROJECT_ROOT, 'post_check_firewall_rule_paloalto.yml')
ANSIBLE_POST_CHECK_FORTINET_PLAYBOOK = os.path.join(PROJECT_ROOT, 'post_check_firewall_rule_fortinet.yml')

ANSIBLE_PRE_CHECK_PALOALTO_PLAYBOOK = os.path.join(PROJECT_ROOT, 'pre_check_firewall_rule_paloalto.yml')
ANSIBLE_PRE_CHECK_FORTINET_PLAYBOOK = os.path.join(PROJECT_ROOT, 'pre_check_firewall_rule_fortinet.yml')


class NetworkAutomationService:
    """
    A service class to encapsulate all interactions with network automation scripts
    and Ansible playbooks.
    """

    def __init__(self, db_name="network.db"):
        self.db_name = db_name

    def _get_device_type_from_db(self, hostname):
        """Helper to get device type from the network inventory database."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("SELECT device_type FROM devices WHERE hostname = ?", (hostname,))
            result = cursor.fetchone()
            return result[0] if result else None
        except sqlite3.Error as e:
            app_logger.error(f"Database error while getting device type for {hostname}: {e}")
            return None
        finally:
            if conn:
                conn.close()

    def _run_command(self, cmd, cwd=PROJECT_ROOT, error_message="Command failed"):
        """
        Helper method to run a shell command and handle its output/errors.
        Raises an exception if the command fails.
        """
        try:
            app_logger.info(f"Executing command: {' '.join(cmd)} in {cwd}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=cwd)
            app_logger.info(f"Stdout:\n{result.stdout}")
            if result.stderr:
                app_logger.warning(f"Stderr:\n{result.stderr}")
            return result.stdout
        except subprocess.CalledProcessError as e:
            full_error_output = f"Stdout:\n{e.stdout}\nStderr:\n{e.stderr}"
            app_logger.error(f"{error_message}: {full_error_output.strip()}", exc_info=True)
            raise RuntimeError(f"{error_message}: {full_error_output.strip()}") from e
        except FileNotFoundError as e:
            app_logger.error(f"Command not found. Ensure '{cmd[0]}' is in your PATH. Error: {e}", exc_info=True)
            raise RuntimeError(f"Command not found. Ensure '{cmd[0]}' is in your PATH. Error: {e}") from e
        except Exception as e:
            app_logger.critical(f"An unexpected error occurred during command execution: {e}", exc_info=True)
            raise RuntimeError(f"An unexpected error occurred during command execution: {e}") from e

    def run_collector(self):
        """Runs the Ansible collector playbook to gather network data."""
        app_logger.info("NetworkAutomationService: Running Ansible network data collector (collector.yml)...")
        try:
            stdout_collector = self._run_command(['ansible-playbook', ANSIBLE_COLLECTOR_PLAYBOOK, '-i', ANSIBLE_INVENTORY], error_message="Ansible collector playbook failed")
            return {"status": "success", "message": stdout_collector}
        except RuntimeError as e:
            return {"status": "error", "message": str(e)}

    def build_database(self): # This method was missing on your side
        """Runs the database builder script to refresh network data in the DB."""
        app_logger.info("NetworkAutomationService: Running DB builder script (build_db.py)...")
        try:
            stdout_db_builder = self._run_command([sys.executable, DB_BUILDER_SCRIPT], error_message="DB builder script failed")
            return {"status": "success", "message": stdout_db_builder}
        except RuntimeError as e:
            return {"status": "error", "message": str(e)}

    def find_path_and_firewalls(self, source_ip, destination_ip):
        """
        Runs the pathfinder script to determine the network path and identify firewalls.
        Returns a list of firewall hostnames.
        """
        app_logger.info(f"NetworkAutomationService: Running pathfinder for {source_ip} to {destination_ip}...")
        cmd = [sys.executable, PATHFINDER_SCRIPT, source_ip, destination_ip, '--json-output']
        stdout = self._run_command(cmd, error_message="Pathfinder script failed")
        
        try:
            firewalls = json.loads(stdout.strip())
            app_logger.info(f"NetworkAutomationService: Firewalls identified in path: {firewalls}")
            return firewalls
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse pathfinder output JSON: {e}. Raw output: {stdout}") from e

    def check_policy_existence(self, source_ip, destination_ip, protocol, port, firewalls):
        """
        Checks if a firewall policy with the given criteria already exists on the specified firewalls.
        Returns True if a matching policy is found on ANY of the firewalls, False otherwise.
        """
        app_logger.info(f"NetworkAutomationService: Checking for existing policy on {firewalls} for {source_ip}:{port} to {destination_ip} ({protocol})...")
        
        for firewall_hostname in firewalls:
            device_type = self._get_device_type_from_db(firewall_hostname)
            playbook_to_run = None

            if device_type and device_type.lower() == 'firewall':
                if firewall_hostname.startswith('pafw'):
                    playbook_to_run = ANSIBLE_PRE_CHECK_PALOALTO_PLAYBOOK
                elif firewall_hostname.startswith('fgt'):
                    playbook_to_run = ANSIBLE_PRE_CHECK_FORTINET_PLAYBOOK
                # Add other firewall types here if needed

            if playbook_to_run:
                app_logger.info(f"Running pre-check playbook '{playbook_to_run}' for {firewall_hostname}...")
                extra_vars = {
                    'source_ip': source_ip,
                    'destination_ip': destination_ip,
                    'protocol': protocol,
                    'port': port,
                    'firewalls': [firewall_hostname] # Target only this specific host within the playbook's hosts
                }
                extra_vars_json = json.dumps(extra_vars)

                cmd = [
                    'ansible-playbook',
                    playbook_to_run,
                    '-i', ANSIBLE_INVENTORY,
                    '--extra-vars', extra_vars_json
                ]
                
                try:
                    stdout = self._run_command(cmd, error_message=f"Ansible pre-check playbook for {firewall_hostname} failed")
                    if "POLICY_EXISTS_PALOALTO" in stdout or "POLICY_EXISTS_FORTINET" in stdout:
                        app_logger.info(f"NetworkAutomationService: Matching policy found on {firewall_hostname}.")
                        return True # Policy found on at least one firewall
                except RuntimeError as e:
                    app_logger.error(f"NetworkAutomationService: Error during pre-check on {firewall_hostname}: {e}")
                    # Continue to next firewall if one fails during pre-check
            else:
                app_logger.warning(f"No specific pre-check playbook defined for device type of {firewall_hostname} ({device_type}). Skipping pre-check for this device.")
        
        app_logger.info("NetworkAutomationService: No matching policy found on any specified firewall.")
        return False # No policy found on any of the specified firewalls

    def provision_rule(self, rule_data, firewalls):
        """
        Triggers the Ansible provisioning playbooks for a given rule on specified firewalls.
        Iterates through each firewall and calls the corresponding device-specific playbook.
        """
        app_logger.info(f"NetworkAutomationService: Running Ansible provisioning for rule {rule_data['rule_id']} on {firewalls}...")
        
        all_provisioning_successful = True
        detailed_messages = []

        for firewall_hostname in firewalls:
            device_type = self._get_device_type_from_db(firewall_hostname)
            playbook_to_run = None

            if device_type and device_type.lower() == 'firewall':
                if firewall_hostname.startswith('pafw'):
                    playbook_to_run = ANSIBLE_PROVISION_PALOALTO_PLAYBOOK
                elif firewall_hostname.startswith('fgt'):
                    playbook_to_run = ANSIBLE_PROVISION_FORTINET_PLAYBOOK
                # Add other firewall types here if needed

            if playbook_to_run:
                app_logger.info(f"Running provisioning playbook '{playbook_to_run}' for {firewall_hostname}...")
                extra_vars = {
                    'rule_id': rule_data['rule_id'],
                    'source_ip': rule_data['source_ip'],
                    'destination_ip': rule_data['destination_ip'],
                    'protocol': rule_data['protocol'],
                    'dest_port': rule_data['port'], # Use 'port' from FirewallRule, passed as dest_port to playbook
                    'rule_description': rule_data['rule_description'],
                    'firewalls': [firewall_hostname] # Target only this specific host within the playbook's hosts
                }
                extra_vars_json = json.dumps(extra_vars)

                cmd = [
                    'ansible-playbook',
                    playbook_to_run,
                    '-i', ANSIBLE_INVENTORY,
                    '--extra-vars', extra_vars_json
                ]
                try:
                    stdout = self._run_command(cmd, error_message=f"Ansible provisioning playbook for {firewall_hostname} failed")
                    detailed_messages.append(f"Provisioning on {firewall_hostname} succeeded:\n{stdout}")
                except RuntimeError as e:
                    all_provisioning_successful = False
                    detailed_messages.append(f"Provisioning on {firewall_hostname} failed: {e}")
                    app_logger.error(f"NetworkAutomationService: Provisioning failed on {firewall_hostname}: {e}")
            else:
                all_provisioning_successful = False
                detailed_messages.append(f"No specific provisioning playbook defined for device type of {firewall_hostname} ({device_type}). Skipping provisioning for this device.")
                app_logger.warning(f"NetworkAutomationService: No specific provisioning playbook for {firewall_hostname}.")
        
        if all_provisioning_successful:
            return "\n".join(detailed_messages) # Return combined stdout if all successful
        else:
            raise RuntimeError("One or more firewalls failed to provision:\n" + "\n".join(detailed_messages))

    def post_check_rule(self, rule_data, firewalls):
        """
        Triggers the Ansible post-check playbooks for a given rule on specified firewalls.
        Iterates through each firewall and calls the corresponding device-specific playbook.
        """
        app_logger.info(f"NetworkAutomationService: Running Ansible post-check for rule {rule_data['rule_id']} on {firewalls}...")
        
        all_post_checks_successful = True
        detailed_messages = []

        for firewall_hostname in firewalls:
            device_type = self._get_device_type_from_db(firewall_hostname)
            playbook_to_run = None

            if device_type and device_type.lower() == 'firewall':
                if firewall_hostname.startswith('pafw'):
                    playbook_to_run = ANSIBLE_POST_CHECK_PALOALTO_PLAYBOOK
                elif firewall_hostname.startswith('fgt'):
                    playbook_to_run = ANSIBLE_POST_CHECK_FORTINET_PLAYBOOK
                # Add other firewall types here if needed

            if playbook_to_run:
                app_logger.info(f"Running post-check playbook '{playbook_to_run}' for {firewall_hostname}...")
                extra_vars = {
                    'rule_id': rule_data['rule_id'],
                    'source_ip': rule_data['source_ip'],
                    'destination_ip': rule_data['destination_ip'],
                    'protocol': rule_data['protocol'],
                    'dest_port': rule_data['port'], # Use 'port' from FirewallRule, passed as dest_port to playbook
                    'firewalls': [firewall_hostname] # Target only this specific host within the playbook's hosts
                }
                extra_vars_json = json.dumps(extra_vars)

                cmd = [
                    'ansible-playbook',
                    playbook_to_run,
                    '-i', ANSIBLE_INVENTORY,
                    '--extra-vars', extra_vars_json
                ]
                try:
                    stdout = self._run_command(cmd, error_message=f"Ansible post-check playbook for {firewall_hostname} failed")
                    detailed_messages.append(f"Post-check on {firewall_hostname} succeeded:\n{stdout}")
                except RuntimeError as e:
                    all_post_checks_successful = False
                    detailed_messages.append(f"Post-check on {firewall_hostname} failed: {e}")
                    app_logger.error(f"NetworkAutomationService: Post-check failed on {firewall_hostname}: {e}")
            else:
                all_post_checks_successful = False
                detailed_messages.append(f"No specific post-check playbook defined for device type of {firewall_hostname} ({device_type}). Skipping post-check for this device.")
                app_logger.warning(f"NetworkAutomationService: No specific post-check playbook for {firewall_hostname}.")
        
        if all_post_checks_successful:
            return "\n".join(detailed_messages) # Return combined stdout if all successful
        else:
            raise RuntimeError("One or more firewalls failed post-check:\n" + "\n".join(detailed_messages))
