import subprocess
import os
import json
import logging
import yaml
import ipaddress
import re

app_logger = logging.getLogger(__name__)

OUTPUTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'outputs')

class NetworkAutomationService:
    def __init__(self, inventory_path='inventory.yml', playbook_dir='.'):
        project_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
        self.inventory_path = os.path.join(project_root, inventory_path)
        self.playbook_dir = os.path.join(project_root, playbook_dir)

        if not os.path.exists(self.inventory_path):
            app_logger.error(f"Inventory file not found at: {self.inventory_path}")
            raise FileNotFoundError(f"Inventory file not found at: {self.inventory_path}")

        os.makedirs(OUTPUTS_DIR, exist_ok=True)
        app_logger.info(f"Ansible outputs directory set to: {OUTPUTS_DIR}")

    def _execute_ansible_playbook(self, playbook_name, extra_vars=None):
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

        env_for_subprocess = os.environ.copy()

        user_home = env_for_subprocess.get('HOME', '/tmp')
        ansible_runtime_tmp_dir = os.path.join(user_home, '.ansible_runtime_temps')

        # --- NEW DEBUG LINE HERE ---
        app_logger.debug(f"DEBUGGING PATHS: Determined user_home='{user_home}', ansible_runtime_tmp_dir='{ansible_runtime_tmp_dir}' before os.makedirs.")
        # --- END NEW DEBUG LINE ---

        try:
            # This is the line that might be failing if ansible_runtime_tmp_dir is '/nonexistent'
            os.makedirs(ansible_runtime_tmp_dir, exist_ok=True)
        except Exception as e:
            app_logger.error(f"Failed to create temporary directory '{ansible_runtime_tmp_dir}': {e}")
            # Re-raise the exception to propagate the error
            raise

        env_for_subprocess['ANSIBLE_TMPDIR'] = ansible_runtime_tmp_dir
        env_for_subprocess['TMPDIR'] = ansible_runtime_tmp_dir
        env_for_subprocess['ANSIBLE_COLLECTIONS_PATH'] = os.path.join(self.playbook_dir, 'ansible_collections')

        app_logger.debug("--- Subprocess Environment for Ansible ---")
        for key, value in env_for_subprocess.items():
            if any(kw in key.upper() for kw in ['ANSIBLE', 'TMP', 'TEMP', 'PATH', 'HOME', 'USER', 'COLLECTION']):
                app_logger.debug(f"  {key}={value}")
        app_logger.debug("----------------------------------------")
        app_logger.info(f"Executing Ansible command: {' '.join(command)} in CWD: {self.playbook_dir}")

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                cwd=self.playbook_dir,
                env=env_for_subprocess
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
        app_logger.info("Running Ansible network data collector (collector.yml)...")
        try:
            stdout, stderr = self._execute_ansible_playbook('collector.yml')
            app_logger.info("Network data collection completed.")
            return {"status": "success", "message": "Network data collected.", "stdout": stdout, "stderr": stderr}
        except RuntimeError as e:
            app_logger.error(f"Failed to collect network data: {e}")
            return {"status": "error", "message": f"Failed to collect network data: {e}"}

    def build_database(self):
        app_logger.info("Building network topology database (build_db.py)...")
        try:
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
            raise RuntimeError("Database builder script or Python interpreter not found.")
        except Exception as e:
            app_logger.critical(f"An unexpected error occurred during database build: {e}")
            return {"status": "error", "message": f"An unexpected error occurred during database build: {e}"}

    def find_path_and_firewalls(self, source_ip, destination_ip):
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
                try:
                    firewalls = json.loads(process.stdout.strip())
                    if not isinstance(firewalls, list):
                        firewalls = []
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
        app_logger.info(f"Checking policy existence for {source_ip} to {destination_ip}:{port}/{protocol} on firewalls: {firewalls}")
        
        firewalls_to_provision = []
        firewalls_already_configured = []

        if not firewalls:
            app_logger.info("No firewalls in path. No policies to check.")
            return {
                "firewalls_to_provision": [],
                "firewalls_already_configured": [],
                "all_policies_exist": True
            }

        for firewall_name in firewalls:
            extra_vars = {
                'firewall_name': firewall_name,
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'protocol': protocol,
                'port': port
            }

            playbook = None
            if 'pafw' in firewall_name.lower():
                playbook = 'pre_check_firewall_rule_paloalto.yml'
            elif 'fgt' in firewall_name.lower():
                playbook = 'pre_check_firewall_rule_fortinet.yml'
            else:
                app_logger.warning(f"Unknown firewall type for {firewall_name}. Cannot perform pre-check.")
                firewalls_to_provision.append(firewall_name)
                continue

            try:
                stdout, stderr = self._execute_ansible_playbook(playbook, extra_vars=extra_vars)
                
                if "POLICY_EXISTS" in stdout:
                    app_logger.info(f"Policy EXISTS on {firewall_name}.")
                    firewalls_already_configured.append(firewall_name)
                else:
                    app_logger.info(f"Policy DOES NOT exist on {firewall_name}.")
                    firewalls_to_provision.append(firewall_name)

            except RuntimeError as e:
                app_logger.error(f"Pre-check for policy existence failed on {firewall_name}: {e}. Assuming needs provisioning.")
                firewalls_to_provision.append(firewall_name)
            except Exception as e:
                app_logger.critical(f"Unexpected error during policy existence check on {firewall_name}: {e}. Assuming needs provisioning.")
                firewalls_to_provision.append(firewall_name)
        
        all_policies_exist_flag = len(firewalls_to_provision) == 0

        if all_policies_exist_flag:
            app_logger.info("Policy confirmed to exist on ALL specified firewalls in the path.")
        else:
            app_logger.info(f"Policy does NOT exist on all specified firewalls. Firewalls to provision: {firewalls_to_provision}")
            
        return {
            "firewalls_to_provision": firewalls_to_provision,
            "firewalls_already_configured": firewalls_already_configured,
            "all_policies_exist": all_policies_exist_flag
        }


    def provision_rule(self, rule_data, firewalls):
        app_logger.info(f"Initiating provisioning for rule ID {rule_data['rule_id']} on firewalls: {firewalls}")
        
        provision_stdout = ""
        provision_stderr = ""

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
            
            playbook = None
            if 'pafw' in firewall_name.lower():
                playbook = 'provision_firewall_rule_paloalto.yml'
            elif 'fgt' in firewall_name.lower():
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
                raise

        return provision_stdout


    def post_check_rule(self, rule_data, firewalls):
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
                
                if "POLICY_VERIFIED" in stdout:
                    app_logger.info(f"Rule {rule_data['rule_id']} successfully verified on {firewall_name}.")
                else:
                    app_logger.warning(f"Rule {rule_data['rule_id']} NOT verified on {firewall_name}. Check Ansible output.")
                    raise RuntimeError(f"Post-check verification failed on {firewall_name}.")

            except RuntimeError as e:
                app_logger.error(f"Failed to post-check rule {rule_data['rule_id']} on {firewall_name}: {e}")
                raise
            except Exception as e:
                app_logger.critical(f"An unexpected error occurred during post-check for rule {rule_data['rule_id']} on {firewall_name}: {e}")
                raise

        return post_check_stdout
