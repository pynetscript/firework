import subprocess
import os
import json
import logging

# Get a logger for this module
app_logger = logging.getLogger(__name__)

class NetworkAutomationService:
    def __init__(self, inventory_path='inventory.yml', playbook_dir='.'):
        # Calculate the path to the project root (up two levels from app/services)
        project_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')

        self.inventory_path = os.path.join(project_root, inventory_path)
        self.playbook_dir = os.path.join(project_root, playbook_dir) # Playbooks are also in the project root

        # Ensure inventory.yml exists as a prerequisite for Ansible operations
        if not os.path.exists(self.inventory_path):
            app_logger.error(f"Inventory file not found at: {self.inventory_path}")
            raise FileNotFoundError(f"Inventory file not found at: {self.inventory_path}")

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
            # Convert extra_vars dict to a JSON string for Ansible's --extra-vars
            command.extend(['--extra-vars', json.dumps(extra_vars)])

        app_logger.info(f"Executing Ansible command: {' '.join(command)} in {self.playbook_dir}")

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True, # Raise a CalledProcessError for non-zero exit codes
                cwd=self.playbook_dir # Execute from the project root
            )
            app_logger.info(f"Ansible playbook '{playbook_name}' executed successfully.")
            app_logger.debug(f"STDOUT for {playbook_name}:\n{process.stdout}")
            if process.stderr:
                app_logger.warning(f"STDERR for {playbook_name}:\n{process.stderr}")
            return process.stdout, process.stderr
        except subprocess.CalledProcessError as e:
            app_logger.error(f"Ansible playbook '{playbook_name}' failed with exit code {e.returncode}.")
            app_logger.error(f"STDOUT from failure:\n{e.stdout}")
            app_logger.error(f"STDERR from failure:\n{e.stderr}")
            raise RuntimeError(f"Ansible playbook '{playbook_name}' failed: {e.stderr or e.stdout}")
        except FileNotFoundError:
            app_logger.critical("Ansible command not found. Is Ansible installed and in your PATH?")
            raise RuntimeError("Ansible command not found. Please ensure Ansible is installed.")
        except Exception as e:
            app_logger.critical(f"An unexpected error occurred during Ansible execution for {playbook_name}: {e}")
            raise RuntimeError(f"An unexpected error occurred during Ansible execution: {e}")

    def run_collector(self):
        """Runs the Ansible playbook to collect network device data."""
        app_logger.info("Running Ansible network data collector (collector.yml)...")
        try:
            stdout, stderr = self._execute_ansible_playbook('collector.yml')
            app_logger.info("Network data collection completed.")
            return {"status": "success", "message": "Network data collected.", "stdout": stdout, "stderr": stderr}
        except RuntimeError as e:
            app_logger.error(f"Failed to collect network data: {e}")
            return {"status": "error", "message": f"Failed to collect network data: {e}"}

    def build_database(self):
        """Runs the Python script to build the network topology database."""
        app_logger.info("Building network topology database (build_db.py)...")
        try:
            # Assuming build_db.py is in the same directory as this service or accessible via path
            build_db_script_path = os.path.join(self.playbook_dir, 'build_db.py')
            if not os.path.exists(build_db_script_path):
                app_logger.error(f"Database builder script not found: {build_db_script_path}")
                raise FileNotFoundError(f"Database builder script not found: {build_db_script_path}")

            process = subprocess.run(
                ['python3', build_db_script_path],
                capture_output=True,
                text=True,
                check=True,
                cwd=self.playbook_dir
            )
            app_logger.info("Network topology database built successfully.")
            app_logger.debug(f"STDOUT from build_db.py:\n{process.stdout}")
            if process.stderr:
                app_logger.warning(f"STDERR from build_db.py:\n{process.stderr}")
            return {"status": "success", "message": "Database built.", "stdout": process.stdout, "stderr": process.stderr}
        except subprocess.CalledProcessError as e:
            app_logger.error(f"Database builder script failed with exit code {e.returncode}.")
            app_logger.error(f"STDOUT from failure:\n{e.stdout}")
            app_logger.error(f"STDERR from failure:\n{e.stderr}")
            return {"status": "error", "message": f"Database build failed: {e.stderr or e.stdout}"}
        except FileNotFoundError:
            app_logger.critical("Python interpreter or build_db.py script not found.")
            return {"status": "error", "message": "Database builder script or Python interpreter not found."}
        except Exception as e:
            app_logger.critical(f"An unexpected error occurred during database build: {e}")
            return {"status": "error", "message": f"An unexpected error occurred during database build: {e}"}

    def find_path_and_firewalls(self, source_ip, destination_ip):
        """
        Runs the Python pathfinder script to identify firewalls in the path.
        Returns a list of firewall hostnames.
        """
        app_logger.info(f"Running pathfinder (pathfinder.py) for {source_ip} to {destination_ip}...")
        try:
            pathfinder_script_path = os.path.join(self.playbook_dir, 'pathfinder.py')
            if not os.path.exists(pathfinder_script_path):
                app_logger.error(f"Pathfinder script not found: {pathfinder_script_path}")
                raise FileNotFoundError(f"Pathfinder script not found: {pathfinder_script_path}")
                
            process = subprocess.run(
                ['python3', pathfinder_script_path, source_ip, destination_ip, '--json-output'],
                capture_output=True,
                text=True,
                check=True,
                cwd=self.playbook_dir
            )
            firewalls = []
            if process.stdout:
                # Assuming pathfinder.py outputs a JSON array of firewall hostnames
                try:
                    firewalls = json.loads(process.stdout.strip())
                    if not isinstance(firewalls, list):
                        firewalls = [] # Ensure it's a list even if JSON is not array
                except json.JSONDecodeError:
                    app_logger.error(f"Pathfinder output is not valid JSON: {process.stdout.strip()}")
                    firewalls = []
            
            app_logger.info(f"Pathfinder completed. Firewalls found: {firewalls}")
            app_logger.debug(f"STDOUT from pathfinder.py:\n{process.stdout}")
            if process.stderr:
                app_logger.warning(f"STDERR from pathfinder.py:\n{process.stderr}")

            return firewalls
        except subprocess.CalledProcessError as e:
            app_logger.error(f"Pathfinder script failed with exit code {e.returncode}.")
            app_logger.error(f"STDOUT from failure:\n{e.stdout}")
            app_logger.error(f"STDERR from failure:\n{e.stderr}")
            raise RuntimeError(f"Pathfinder failed: {e.stderr or e.stdout}")
        except FileNotFoundError:
            app_logger.critical("Python interpreter or pathfinder.py script not found.")
            raise RuntimeError("Pathfinder script or Python interpreter not found.")
        except Exception as e:
            app_logger.critical(f"An unexpected error occurred during pathfinding: {e}")
            raise RuntimeError(f"An unexpected error occurred during pathfinding: {e}")


    def check_policy_existence(self, source_ip, destination_ip, protocol, port, firewalls):
        """
        Checks if a given policy already exists on the specified firewalls.
        Returns True if policy exists on ANY firewall, False otherwise.
        """
        app_logger.info(f"Checking policy existence for {source_ip} to {destination_ip}:{port}/{protocol} on firewalls: {firewalls}")
        # Iterate through each firewall and check policy existence
        for firewall_name in firewalls:
            extra_vars = {
                'firewall_name': firewall_name, # Pass the single firewall name
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'protocol': protocol,
                'port': port
            }

            # Determine playbook based on firewall_name
            if 'pafw' in firewall_name.lower(): # Example for Palo Alto
                playbook = 'pre_check_firewall_rule_paloalto.yml'
            elif 'fgt' in firewall_name.lower(): # Example for Fortinet
                playbook = 'pre_check_firewall_rule_fortinet.yml'
            else:
                app_logger.warning(f"Unknown firewall type for {firewall_name}. Skipping pre-check.")
                continue
            
            try:
                # Use a specific playbook for checking policy existence
                stdout, stderr = self._execute_ansible_playbook(playbook, extra_vars=extra_vars)
                # The playbook should output "POLICY_EXISTS" or similar if found
                if "POLICY_EXISTS" in stdout:
                    app_logger.info(f"Policy already exists on {firewall_name}.")
                    return True # Policy exists on at least one firewall
            except RuntimeError as e:
                app_logger.error(f"Pre-check for policy existence failed on {firewall_name}: {e}")
                # Continue to next firewall, or re-raise if this is a critical failure
            except Exception as e:
                app_logger.critical(f"Unexpected error during policy existence check on {firewall_name}: {e}")
                # Continue or re-raise

        app_logger.info("Policy does not exist on any of the specified firewalls (or check failed for some).")
        return False


    def provision_rule(self, rule_data, firewalls):
        """Provisions a firewall rule using Ansible based on identified firewalls."""
        app_logger.info(f"Initiating provisioning for rule ID {rule_data['rule_id']} on firewalls: {firewalls}")
        
        provision_stdout = ""
        provision_stderr = ""

        # Loop through each firewall and run the appropriate provisioning playbook
        for firewall_name in firewalls:
            extra_vars = {
                'firewall_name': firewall_name,
                'rule_id': rule_data['rule_id'],
                'source_ip': rule_data['source_ip'],
                'destination_ip': rule_data['destination_ip'],
                'protocol': rule_data['protocol'],
                'dest_port': rule_data['port'],
                'rule_description': rule_data['rule_description']
            }
            
            # Determine playbook based on firewall_name (or other logic from inventory/DB)
            if 'pafw' in firewall_name.lower(): # Example for Palo Alto
                playbook = 'provision_firewall_rule_paloalto.yml'
            elif 'fgt' in firewall_name.lower(): # Example for Fortinet
                playbook = 'provision_firewall_rule_fortinet.yml'
            else:
                app_logger.warning(f"Unknown firewall type for {firewall_name}. Skipping provisioning.")
                continue

            app_logger.info(f"Provisioning rule {rule_data['rule_id']} on {firewall_name} using {playbook}...")
            try:
                stdout, stderr = self._execute_ansible_playbook(playbook, extra_vars=extra_vars)
                provision_stdout += f"\n--- {firewall_name} STDOUT ---\n" + stdout
                provision_stderr += f"\n--- {firewall_name} STDERR ---\n" + stderr
                app_logger.info(f"Successfully provisioned rule {rule_data['rule_id']} on {firewall_name}.")
            except RuntimeError as e:
                app_logger.error(f"Failed to provision rule {rule_data['rule_id']} on {firewall_name}: {e}")
                raise # Re-raise to indicate overall provisioning failure

        return provision_stdout # Return combined stdout for display/logging


    def post_check_rule(self, rule_data, firewalls):
        """Performs a post-check on a provisioned firewall rule using Ansible."""
        app_logger.info(f"Initiating post-check for rule ID {rule_data['rule_id']} on firewalls: {firewalls}")
        
        post_check_stdout = ""
        post_check_stderr = ""

        for firewall_name in firewalls:
            extra_vars = {
                'firewall_name': firewall_name,
                'rule_id': rule_data['rule_id'],
                'source_ip': rule_data['source_ip'],
                'destination_ip': rule_data['destination_ip'],
                'protocol': rule_data['protocol'],
                'dest_port': rule_data['port']
            }

            if 'pafw' in firewall_name.lower():
                playbook = 'post_check_firewall_rule_paloalto.yml'
            elif 'fgt' in firewall_name.lower():
                playbook = 'post_check_firewall_rule_fortinet.yml'
            else:
                app_logger.warning(f"Unknown firewall type for {firewall_name}. Skipping post-check.")
                continue

            app_logger.info(f"Post-checking rule {rule_data['rule_id']} on {firewall_name} using {playbook}...")
            try:
                stdout, stderr = self._execute_ansible_playbook(playbook, extra_vars=extra_vars)
                post_check_stdout += f"\n--- {firewall_name} STDOUT ---\n" + stdout
                post_check_stderr += f"\n--- {firewall_name} STDERR ---\n" + stderr
                
                # Check for a specific string in stdout indicating successful post-check
                if "POLICY_VERIFIED" in stdout: # Playbook should output this if verification passes
                    app_logger.info(f"Rule {rule_data['rule_id']} successfully verified on {firewall_name}.")
                else:
                    app_logger.warning(f"Rule {rule_data['rule_id']} NOT verified on {firewall_name}. Check Ansible output.")
                    raise RuntimeError(f"Post-check verification failed on {firewall_name}.")

            except RuntimeError as e:
                app_logger.error(f"Failed to post-check rule {rule_data['rule_id']} on {firewall_name}: {e}")
                raise # Re-raise to indicate overall post-check failure
            except Exception as e:
                app_logger.critical(f"An unexpected error occurred during post-check for rule {rule_data['rule_id']} on {firewall_name}: {e}")
                raise

        return post_check_stdout # Return combined stdout for display/logging
