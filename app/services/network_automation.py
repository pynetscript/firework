import subprocess
import os
import json
import sys

# Define paths to your scripts and inventory relative to the project root
# This service assumes it's located within 'app/services/'
# and the network automation scripts/playbooks are in the project root.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
ANSIBLE_INVENTORY = os.path.join(PROJECT_ROOT, 'inventory.yml')
ANSIBLE_COLLECTOR_PLAYBOOK = os.path.join(PROJECT_ROOT, 'collector.yml')
DB_BUILDER_SCRIPT = os.path.join(PROJECT_ROOT, 'build_db.py')
PATHFINDER_SCRIPT = os.path.join(PROJECT_ROOT, 'pathfinder.py')
ANSIBLE_PROVISION_PLAYBOOK = os.path.join(PROJECT_ROOT, 'provision_firewall_rule.yml')
ANSIBLE_POST_CHECK_PLAYBOOK = os.path.join(PROJECT_ROOT, 'post_check_firewall_rule.yml')
ANSIBLE_PRE_CHECK_PLAYBOOK = os.path.join(PROJECT_ROOT, 'pre_check_firewall_rule.yml') # Renamed from ANSIBLE_CHECK_POLICY_PLAYBOOK

class NetworkAutomationService:
    """
    A service class to encapsulate all interactions with network automation scripts
    and Ansible playbooks.
    """

    def _run_command(self, cmd, cwd=PROJECT_ROOT, error_message="Command failed"):
        """
        Helper method to run a shell command and handle its output/errors.
        Raises an exception if the command fails.
        """
        try:
            print(f"Executing command: {' '.join(cmd)} in {cwd}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=cwd)
            print(f"Stdout:\n{result.stdout}")
            if result.stderr:
                print(f"Stderr:\n{result.stderr}")
            return result.stdout
        except subprocess.CalledProcessError as e:
            # Include both stdout and stderr in the error message for better debugging
            full_error_output = f"Stdout:\n{e.stdout}\nStderr:\n{e.stderr}"
            raise RuntimeError(f"{error_message}: {full_error_output.strip()}") from e
        except FileNotFoundError as e:
            raise RuntimeError(f"Command not found. Ensure '{cmd[0]}' is in your PATH. Error: {e}") from e
        except Exception as e:
            raise RuntimeError(f"An unexpected error occurred during command execution: {e}") from e

    def run_collector(self):
        """Runs the Ansible collector playbook to gather network data."""
        print("NetworkAutomationService: Running Ansible network data collector (collector.yml)...")
        try:
            stdout = self._run_command(['ansible-playbook', ANSIBLE_COLLECTOR_PLAYBOOK, '-i', ANSIBLE_INVENTORY], error_message="Ansible collector playbook failed")
            return {"status": "success", "message": stdout}
        except RuntimeError as e:
            return {"status": "error", "message": str(e)}

    def build_database(self):
        """Runs the database builder script to refresh network data in the DB."""
        print("NetworkAutomationService: Running DB builder script (build_db.py)...")
        try:
            stdout = self._run_command([sys.executable, DB_BUILDER_SCRIPT], error_message="DB builder script failed")
            return {"status": "success", "message": stdout}
        except RuntimeError as e:
            return {"status": "error", "message": str(e)}

    def find_path_and_firewalls(self, source_ip, destination_ip):
        """
        Runs the pathfinder script to determine the network path and identify firewalls.
        Returns a list of firewall hostnames.
        """
        print(f"NetworkAutomationService: Running pathfinder for {source_ip} to {destination_ip}...")
        cmd = [sys.executable, PATHFINDER_SCRIPT, source_ip, destination_ip, '--json-output']
        stdout = self._run_command(cmd, error_message="Pathfinder script failed")
        
        try:
            firewalls = json.loads(stdout.strip())
            print(f"NetworkAutomationService: Firewalls identified in path: {firewalls}")
            return firewalls
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse pathfinder output JSON: {e}. Raw output: {stdout}") from e

    def check_policy_existence(self, source_ip, destination_ip, protocol, dest_port, firewalls):
        """
        Checks if a firewall policy with the given criteria already exists on the specified firewalls.
        Returns True if a matching policy is found, False otherwise.
        """
        print(f"NetworkAutomationService: Checking for existing policy on {firewalls} for {source_ip}:{dest_port} to {destination_ip} ({protocol})...")
        
        extra_vars = {
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'protocol': protocol,
            'dest_port': dest_port, 
            'firewalls': firewalls # Target these firewalls for the check
        }
        extra_vars_json = json.dumps(extra_vars)

        cmd = [
            'ansible-playbook',
            ANSIBLE_PRE_CHECK_PLAYBOOK,
            '-i', ANSIBLE_INVENTORY,
            '--extra-vars', extra_vars_json
        ]
        
        try:
            stdout = self._run_command(cmd, error_message="Ansible policy check playbook failed")
            # The check_firewall_policy.yml playbook will print "POLICY_EXISTS" if found.
            # We check for this specific string in the stdout.
            if "POLICY_EXISTS" in stdout:
                print("NetworkAutomationService: Matching policy found.")
                return True
            else:
                print("NetworkAutomationService: No matching policy found.")
                return False
        except RuntimeError as e:
            print(f"NetworkAutomationService: Error during policy existence check: {e}")
            # If the playbook itself fails (e.g., connectivity), we treat it as not found for now
            # or could propagate the error if a more strict check is needed.
            return False


    def provision_rule(self, rule_data, firewalls):
        """
        Triggers the Ansible provisioning playbook for a given rule on specified firewalls.
        rule_data should be a dict containing source_ip, destination_ip, protocol, dest_port, rule_id.
        firewalls is a list of hostnames.
        """
        print(f"NetworkAutomationService: Running Ansible provisioning playbook ({ANSIBLE_PROVISION_PLAYBOOK}) for rule {rule_data['rule_id']}...")
        
        extra_vars = {
            'rule_id': rule_data['rule_id'],
            'source_ip': rule_data['source_ip'],
            'destination_ip': rule_data['destination_ip'],
            'protocol': rule_data['protocol'],
            'dest_port': rule_data['dest_port'],
            'firewalls': firewalls, # THIS IS THE CRITICAL KEY
            'rule_description': f"Rule for ticket #{rule_data['rule_id']}"
        }
        extra_vars_json = json.dumps(extra_vars)

        cmd = [
            'ansible-playbook',
            ANSIBLE_PROVISION_PLAYBOOK,
            '-i', ANSIBLE_INVENTORY,
            '--extra-vars', extra_vars_json
        ]
        return self._run_command(cmd, error_message="Ansible provisioning playbook failed")

    def post_check_rule(self, rule_data, firewalls):
        """
        Triggers the Ansible post-check playbook for a given rule on specified firewalls.
        rule_data should be a dict containing source_ip, destination_ip, protocol, dest_port, rule_id.
        firewalls is a list of hostnames.
        """
        print(f"NetworkAutomationService: Running Ansible post-check playbook ({ANSIBLE_POST_CHECK_PLAYBOOK}) for rule {rule_data['rule_id']}...")
        
        extra_vars = {
            'rule_id': rule_data['rule_id'],
            'source_ip': rule_data['source_ip'],
            'destination_ip': rule_data['destination_ip'],
            'protocol': rule_data['protocol'],
            'dest_port': rule_data['dest_port'],
            'firewalls': firewalls # THIS IS THE CRITICAL KEY
        }
        extra_vars_json = json.dumps(extra_vars)

        cmd = [
            'ansible-playbook',
            ANSIBLE_POST_CHECK_PLAYBOOK,
            '-i', ANSIBLE_INVENTORY,
            '--extra-vars', extra_vars_json
        ]
        return self._run_command(cmd, error_message="Ansible post-check playbook failed")

