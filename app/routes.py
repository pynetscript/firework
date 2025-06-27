from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, abort
from app.models import FirewallRule, BlacklistRule, db, User
import ipaddress
import json
import logging
from datetime import datetime
from flask_login import login_required, current_user
from app.services.network_automation import NetworkAutomationService
from app.decorators import roles_required, no_self_approval
import os

routes = Blueprint('routes', __name__)

app_logger = logging.getLogger(__name__)

# Helper function to get the NetworkAutomationService instance attached to the blueprint.
def get_network_automation_service():
    """
    Retrieves the NetworkAutomationService instance attached to the blueprint.
    This instance is created and managed by the Flask app factory (`create_app`).
    """
    if not hasattr(routes, 'network_automation_service'):
        app_logger.warning("NetworkAutomationService not found on blueprint. Creating a fallback instance.")
        routes.network_automation_service = NetworkAutomationService()
    return routes.network_automation_service


@routes.route('/')
def home():
    """
    Redirects unauthenticated users to the login page.
    Redirects authenticated users to the task results page.
    """
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    return redirect(url_for('routes.task_results'))

@routes.route('/request-form')
@login_required
@roles_required('superadmin', 'admin', 'requester', 'approver', 'implementer')
def request_form():
    """
    Renders the form for submitting a new network rule request.
    Accessible by superadmin, admin, requester, approver, and implementer roles.
    """
    return render_template('request_form.html')

@routes.route('/submit-request', methods=['POST'])
@login_required
@roles_required('superadmin', 'admin', 'requester', 'approver', 'implementer')
def submit_request():
    """
    Handles the submission of a new network rule request.
    Performs validation, blacklist checks, initiates a pre-check,
    creates the rule in the DB, and determines initial status based on pre-check results and roles.
    """
    app_logger.info(f"Received new network request from {current_user.username}")
    source_ip = request.form.get('source_ip')
    destination_ip = request.form.get('destination_ip')
    protocol = request.form.get('protocol')
    ports_raw = request.form.get('ports')
    rule_description = request.form.get('rule_description')

    errors = []

    # Validate IP addresses
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        errors.append('Invalid Source IP address format.')
    
    try:
        ipaddress.ip_address(destination_ip)
    except ValueError:
        errors.append('Invalid Destination IP address format.')

    # Validate protocol (simple check)
    allowed_protocols = ['tcp', 'udp', 'icmp', 'any', '6', '17', '1']
    if protocol.lower() not in allowed_protocols and not protocol.isdigit():
        errors.append('Invalid Protocol. Must be tcp, udp, icmp, any, or a protocol number.')
    
    # Process ports: Allow only a single port (0-65535) or the string "any"
    ports = []
    if protocol.lower() in ['icmp', 'any', '1']:
        ports = ['any'] # For ICMP or ANY protocol, ports are 'any'
    elif ports_raw:
        ports_raw_lower = ports_raw.strip().lower()
        if ports_raw_lower == 'any':
            ports = ['any']
        else:
            try:
                port_num = int(ports_raw)
                if 0 <= port_num <= 65535:
                    ports = [str(port_num)] # Store as string in list for consistency with 'any'
                else:
                    errors.append(f'Invalid port: {ports_raw}. Must be a number between 0-65535 or "any".')
            except ValueError:
                errors.append(f'Invalid port: {ports_raw}. Must be a number between 0-65535 or "any".')
    
    if not ports and protocol.lower() not in ['icmp', 'any', '1']:
        errors.append('Port is required for the specified protocol. Must be a number between 0-65535 or "any".')


    if errors:
        for error in errors:
            flash(error, 'error')
        app_logger.warning(f"Validation errors for new request from {current_user.username}: {errors}")
        return jsonify({"status": "error", "message": "Validation failed", "errors": errors}), 400

    # Blacklist check
    try:
        blacklisted = False
        blacklist_rules = BlacklistRule.query.filter_by(enabled=True).order_by(BlacklistRule.sequence.asc()).all()

        for rule in blacklist_rules:
            ip_match = True
            protocol_match = True
            port_match = True

            # Source IP check
            if rule.source_ip:
                try:
                    if '/' in rule.source_ip: # CIDR notation
                        if not ipaddress.ip_address(source_ip) in ipaddress.ip_network(rule.source_ip):
                            ip_match = False
                    else: # Single IP
                        if source_ip != rule.source_ip:
                            ip_match = False
                except ValueError:
                    app_logger.warning(f"Invalid source_ip in blacklist rule {rule.id}: {rule.source_ip}")
                    ip_match = False # Treat as non-match if rule is malformed

            # Destination IP check
            if ip_match and rule.destination_ip: # Only check if source IP matched
                try:
                    if '/' in rule.destination_ip: # CIDR notation
                        if not ipaddress.ip_address(destination_ip) in ipaddress.ip_network(rule.destination_ip):
                            ip_match = False
                    else: # Single IP
                        if destination_ip != rule.destination_ip:
                            ip_match = False
                except ValueError:
                    app_logger.warning(f"Invalid destination_ip in blacklist rule {rule.id}: {rule.destination_ip}")
                    ip_match = False # Treat as non-match if rule is malformed

            # Protocol check
            if ip_match and rule.protocol and rule.protocol.lower() != 'any':
                if protocol.lower() != rule.protocol.lower():
                    protocol_match = False

            # Port check (only if protocol matches)
            # This logic must handle rule.destination_port being 'any', a single port, or a range
            # And requested ports being ['any'] or ['single_port_number_string']
            if ip_match and protocol_match and rule.destination_port: # If rule has a destination port specified
                rule_dest_port_lower = rule.destination_port.lower()
                requested_port_value = ports[0] if ports else None # Get the single requested port (or 'any')

                if requested_port_value == 'any':
                    # If requested is 'any', it matches any rule that specifies a port (whether 'any' or specific)
                    # We assume if a rule.destination_port exists, 'any' request matches it.
                    pass # port_match remains True
                elif rule_dest_port_lower == 'any':
                    # If rule's destination port is 'any', it matches the specific requested port
                    pass # port_match remains True
                else:
                    # Both requested and rule ports are specific (not 'any').
                    # Convert requested port to int. Rule port can be single or range.
                    try:
                        requested_port_int = int(requested_port_value)

                        if '-' in rule_dest_port_lower:
                            start, end = map(int, rule_dest_port_lower.split('-'))
                            if not (start <= requested_port_int <= end):
                                port_match = False
                        else:
                            if requested_port_int != int(rule_dest_port_lower):
                                port_match = False
                    except ValueError:
                        # Should not happen with prior validation, but for robustness
                        app_logger.warning(f"Error parsing port in blacklist check for rule {rule.id}. Requested: {requested_port_value}, Rule: {rule_dest_port_lower}")
                        port_match = False # Treat as non-match if parsing fails


            if ip_match and protocol_match and port_match:
                blacklisted = True
                app_logger.warning(f"Request from {source_ip} to {destination_ip}:{ports_raw}/{protocol} BLOCKED by blacklist rule ID {rule.id} ('{rule.rule_name}') for user {current_user.username}.")
                break # Exit loop if a blacklist rule matches

        if blacklisted:
            flash(f"Your request from {source_ip} to {destination_ip}:{ports_raw}/{protocol} matches a blacklisted pattern and cannot be submitted. Contact an administrator for details.", 'error')
            return jsonify({"status": "error", "message": "Request blocked by blacklist rule."}), 403
        else:
            app_logger.info(f"Request from {source_ip} to {destination_ip}:{ports_raw}/{protocol} passed blacklist check for user {current_user.username}.")

    except Exception as e:
        app_logger.error(f"Error during blacklist check: {e}", exc_info=True)
        flash("An error occurred during the blacklist check. Please try again or contact support.", 'error')
        return jsonify({"status": "error", "message": "Internal error during blacklist check."}), 500

    # Create the new rule with a temporary status before pre-check
    new_rule = FirewallRule(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        ports=ports, # Save as a list
        status='Pending Pre-Check', # Temporary status
        rule_description=rule_description,
        approval_status='Pending Pre-Check', # Temporary status
        requester_id=current_user.id
    )
    db.session.add(new_rule)
    db.session.commit() # Commit to get an ID for the rule, important for pre-check
    app_logger.info(f"Network request ID {new_rule.id} created by {current_user.username} with temporary status 'Pending Pre-Check'.")

    # --- Perform Pre-Check for ALL requests ---
    try:
        all_potential_firewalls = ['pa_firewall_1', 'fgt_firewall_1', 'fgt_firewall_2'] # EXAMPLE: ADJUST THIS

        rule_data_for_precheck = {
            'rule_id': new_rule.id,
            'source_ip': new_rule.source_ip,
            'destination_ip': new_rule.destination_ip,
            'protocol': new_rule.protocol,
            'ports': new_rule.ports,
            'rule_description': rule_description
        }

        stdout, stderr, firewalls_checked = get_network_automation_service().perform_pre_check(
            rule_data=rule_data_for_precheck,
            firewalls_involved=all_potential_firewalls
        )

        # Retrieve the rule again in case it was modified by other processes or to ensure fresh data
        db_rule = FirewallRule.query.get(new_rule.id)
        if db_rule:
            db_rule.firewalls_involved = rule_data_for_precheck.get('firewalls_involved')
            db_rule.firewalls_to_provision = rule_data_for_precheck.get('firewalls_to_provision')
            db_rule.firewalls_already_configured = rule_data_for_precheck.get('firewalls_already_configured')

            if stdout:
                app_logger.info(f"Pre-check STDOUT for rule {db_rule.id}:\n{stdout}")
            if stderr:
                app_logger.error(f"Pre-check STDERR for rule {db_rule.id}:\n{stderr}")

            # Determine final status after pre-check, considering user roles for approval
            if current_user.has_role('superadmin', 'admin'):
                db_rule.approval_status = 'Approved'
                if db_rule.firewalls_to_provision and len(db_rule.firewalls_to_provision) > 0:
                    db_rule.status = 'Approved - Pending Implementation'
                    flash_message = f"Network request ID {db_rule.id} auto-approved and moved to 'Pending Implementation' after pre-check."
                elif db_rule.firewalls_involved and len(db_rule.firewalls_involved) > 0 and \
                     db_rule.firewalls_already_configured and \
                     set(db_rule.firewalls_involved) == set(db_rule.firewalls_already_configured):
                    db_rule.status = 'Completed - No Provisioning Needed'
                    flash_message = f"Network request ID {db_rule.id} auto-approved. Policy already exists. Marked as 'Completed - No Provisioning Needed'."
                else:
                    db_rule.status = 'Approved - No Provisioning Needed'
                    flash_message = f"Network request ID {db_rule.id} auto-approved. No provisioning required."
                app_logger.info(f"User {current_user.username} (role: {current_user.role}) auto-approved request {db_rule.id}.")
            else:
                # For all other roles, it goes to Pending approval after pre-check
                db_rule.approval_status = 'Pending'
                db_rule.status = 'Pending' # Or 'Pending Approval - Pre-Check Completed' if you want more detail
                flash_message = f"Network request ID {db_rule.id} submitted successfully and is now 'Pending' approval after pre-check."
                app_logger.info(f"Network request ID {db_rule.id} moved to 'Pending' approval after pre-check.")

            db.session.commit()
            flash(flash_message, 'success')
            return jsonify({
                "status": "success",
                "message": flash_message,
                "rule_id": db_rule.id,
                "status_detail": db_rule.status, # Approved/Pending/Pending Implementation/etc.
                "approval_status": db_rule.approval_status,
                "can_access_approvals": current_user.has_role('superadmin', 'admin', 'approver'),
                "firewalls_involved": db_rule.firewalls_involved if db_rule.firewalls_involved else []
            }), 200

    except RuntimeError as e:
        db_rule = FirewallRule.query.get(new_rule.id) # Re-fetch in case it was not found earlier
        if db_rule:
            db_rule.status = 'Pre-Check Failed'
            db_rule.approval_status = 'Pre-Check Failed'
            db.session.commit()
        app_logger.error(f"Network automation pre-check failed for rule {new_rule.id}: {e}", exc_info=True)
        flash(f"Pre-check failed: {e}", 'error')
        return jsonify({"status": "error", "message": f"Pre-check failed: {e}"}), 500
    except Exception as e:
        db_rule = FirewallRule.query.get(new_rule.id) # Re-fetch
        if db_rule:
            db_rule.status = 'Error During Pre-Check'
            db_rule.approval_status = 'Error'
            db.session.commit()
        app_logger.critical(f"An unexpected error occurred during network automation pre-check for rule {new_rule.id}: {e}", exc_info=True)
        flash(f"An unexpected error occurred during pre-check: {e}", 'error')
        return jsonify({"status": "error", "message": f"An unexpected error occurred during pre-check: {e}"}), 500

@routes.route('/task-results')
@login_required
def task_results():
    """
    Displays a list of network automation tasks relevant to the current user.
    - Superadmins/Admins see all tasks.
    - Requesters see tasks they have submitted.
    - Implementers see tasks that are 'Approved - Pending Implementation' or 'Provisioning' or 'Provisioning Failed'.
    - Approvers see tasks they have approved or denied.
    """
    query = FirewallRule.query

    # Superadmin/Admin can see all rules
    if current_user.has_role('superadmin') or current_user.has_role('admin'):
        rules = query.all()
    else:
        # Build conditions for other roles using OR
        user_rules_conditions = []

        # Requesters see their own rules
        if current_user.has_role('requester'):
            user_rules_conditions.append(FirewallRule.requester_id == current_user.id)

        # Implementers see rules pending, pending implementation, provisioning, provisioning failed, completed
        if current_user.has_role('implementer'):
            user_rules_conditions.append(
                FirewallRule.status.in_(['Pending', 'Approved - Pending Implementation', 'Provisioning', 'Provisioning Failed', 'Completed'])
            )

	# Approvers see rules they have approved or denied OR rules with statuses like implementers
        if current_user.has_role('approver'):
            user_rules_conditions.append(
                FirewallRule.status.in_(['Pending', 'Approved - Pending Implementation', 'Provisioning', 'Provisioning Failed', 'Completed'])
            )

        # Apply combined conditions, or an empty list if no relevant conditions
        if user_rules_conditions:
            rules = query.filter(db.or_(*user_rules_conditions)).all()
        else:
            rules = [] # If the user has no roles defined to view tasks, show an empty list

    # Sort rules for consistent display (e.g., by creation date, newest first)
    # This line can be adjusted based on desired sorting.
    rules.sort(key=lambda r: r.created_at, reverse=True) 

    return render_template('task_results.html', rules=rules)

@routes.route('/approve-deny-request/<int:rule_id>', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin', 'admin', 'approver')
@no_self_approval # Prevent approvers from approving their own requests
def approve_deny_request(rule_id):
    """
    Allows approvers to review, approve, or deny network rule requests.
    Approval will transition the request to 'Pending Implementation' status
    without triggering automation.
    """
    rule = FirewallRule.query.get_or_404(rule_id)

    # Ensure only pending rules can be acted upon by non-superadmin/admin approvers
    if not current_user.has_role('superadmin', 'admin') and rule.approval_status != 'Pending':
        flash('This request is not pending approval.', 'warning')
        return redirect(url_for('routes.approvals_list'))

    if request.method == 'POST':
        action = request.form.get('action')
        justification = request.form.get('approver_comment')

        rule.approver_id = current_user.id
        rule.approval_justification = justification

        if action == 'approve':
            rule.approval_status = 'Approved'
            rule.status = 'Approved - Pending Implementation'
            rule.approved_at = datetime.utcnow()
            app_logger.info(f"Rule {rule.id} approved by {current_user.username}. Status: {rule.status}.")

            flash(f"Rule {rule.id} approved and moved to 'Pending Implementation'. Automation will be triggered separately.", 'success')

        elif action == 'deny':
            rule.approval_status = 'Denied'
            rule.status = 'Denied'
            flash(f"Rule {rule.id} denied by {current_user.username}.", 'info')
            app_logger.info(f"Rule {rule.id} denied by {current_user.username}.")

        db.session.commit()
        return redirect(url_for('routes.approvals_list'))

    return render_template('approval_detail.html', rule=rule)

@routes.route('/approvals')
@login_required
@roles_required('superadmin', 'admin', 'approver')
def approvals_list():
    """
    Displays a list of network rule requests pending approval (for approvers)
    or all requests that are pending/approved (for superadmins/admins).
    """
    if current_user.has_role('superadmin', 'admin'):
        # Superadmins and Admins can see all rules that are either Pending or Approved
        rules = FirewallRule.query.filter(
            FirewallRule.approval_status.in_(['Pending', 'Approved'])
        ).order_by(FirewallRule.created_at.desc()).all()
    elif current_user.has_role('approver'):
        # Approvers only see rules explicitly pending their action
        rules = FirewallRule.query.filter_by(approval_status='Pending').order_by(FirewallRule.created_at.asc()).all()
    else:
        # Fallback for any other role that might somehow access this (though roles_required should prevent it)
        rules = []
    return render_template('approvals_list.html', rules=rules)

@routes.route('/implement/<int:rule_id>', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin', 'admin', 'implementer')
def implement_rule(rule_id):
    """
    Allows implementers to review and provision network rules.
    Triggers provisioning and post-checks.
    """
    rule = FirewallRule.query.get_or_404(rule_id)

    # Only allow action if status is 'Approved - Pending Implementation' or 'Partially Implemented - Requires Attention'
    if rule.status not in ['Approved - Pending Implementation', 'Partially Implemented - Requires Attention']:
        flash(f"Rule ID {rule_id} is currently '{rule.status}'. No implementation action available.", 'info')
        return redirect(url_for('routes.implementation_list'))

    if request.method == 'POST':
        action = request.form.get('action')
        implementer_comment = request.form.get('implementer_comment')

        rule.implementer_id = current_user.id
        rule.implementer_comment = implementer_comment
        rule.implemented_at = datetime.utcnow()

        if action == 'provision':
            firewalls_to_provision = rule.firewalls_to_provision if rule.firewalls_to_provision else []

            if not firewalls_to_provision:
                flash("No firewalls marked for provisioning for this rule. Marking as 'Completed - No Provisioning Needed'.", 'info')
                rule.status = 'Completed - No Provisioning Needed'
                db.session.commit()
                app_logger.info(f"Rule {rule.id} marked as 'Completed - No Provisioning Needed' by {current_user.username} (no firewalls to provision).")
                return redirect(url_for('routes.implementation_list'))

            try:
                rule.status = 'Provisioning In Progress' # Set status before starting
                db.session.commit() # Commit status change immediately

                # Perform provisioning
                provision_stdout, provision_stderr, successfully_provisioned, failed_provisioning = \
                    get_network_automation_service().provision_firewall_rule(
                        rule_data={
                            'rule_id': rule.id,
                            'source_ip': rule.source_ip,
                            'destination_ip': rule.destination_ip,
                            'protocol': rule.protocol,
                            'ports': rule.ports,
                            'rule_description': rule.rule_description
                        },
                        firewalls_to_provision=firewalls_to_provision
                    )

                if provision_stdout:
                    app_logger.info(f"Provisioning STDOUT for rule {rule.id}:\n{provision_stdout}")
                if provision_stderr:
                    app_logger.error(f"Provisioning STDERR for rule {rule.id}:\n{provision_stderr}")

                rule.firewalls_already_configured = list(set(rule.firewalls_already_configured or []) | set(successfully_provisioned))
                rule.firewalls_to_provision = [fw for fw in firewalls_to_provision if fw not in successfully_provisioned]


                if len(failed_provisioning) == 0:
                    # All provisioned, now perform post-check
                    post_check_stdout, post_check_stderr, verified_firewalls, unverified_firewalls = \
                        get_network_automation_service().perform_post_check(
                            rule_data={
                                'rule_id': rule.id,
                                'source_ip': rule.source_ip,
                                'destination_ip': rule.destination_ip,
                                'protocol': rule.protocol,
                                'ports': rule.ports,
                                'rule_description': rule.rule_description
                            },
                            provisioned_firewalls=successfully_provisioned
                        )
                    if post_check_stdout:
                        app_logger.info(f"Post-check STDOUT for rule {rule.id}:\n{post_check_stdout}")
                    if post_check_stderr:
                        app_logger.error(f"Post-check STDERR for rule {rule.id}:\n{post_check_stderr}")

                    if len(unverified_firewalls) == 0:
                        rule.status = 'Completed'
                        flash(f"Rule ID {rule.id} successfully provisioned and verified on all target firewalls.", 'success')
                    else:
                        rule.status = 'Partially Implemented - Requires Attention'
                        flash(f"Rule ID {rule.id} provisioned but failed verification on some firewalls: {', '.join(unverified_firewalls)}. Please investigate.", 'warning')

                else: # Some provisioning failed
                    if len(successfully_provisioned) > 0:
                        rule.status = 'Partially Implemented - Requires Attention'
                        flash(f"Rule ID {rule.id} partially provisioned. Failed on: {', '.join(failed_provisioning)}. Please investigate.", 'warning')
                    else:
                        rule.status = 'Provisioning Failed'
                        flash(f"Rule ID {rule.id} failed provisioning on all target firewalls: {', '.join(failed_provisioning)}.", 'error')

                db.session.commit()
                app_logger.info(f"Implementer {current_user.username} (ID: {current_user.id}) processed rule {rule.id}. Final status: {rule.status}.")

            except RuntimeError as e:
                rule.status = 'Implementation Failed - Automation Error'
                db.session.commit()
                app_logger.error(f"Automation failed during provisioning/post-check for rule {rule.id}: {e}", exc_info=True)
                flash(f"Implementation failed due to automation error: {e}", 'error')
            except Exception as e:
                rule.status = 'Implementation Failed - Unexpected Error'
                db.session.commit()
                app_logger.critical(f"An unexpected error occurred during implementation for rule {rule.id}: {e}", exc_info=True)
                flash(f"An unexpected error occurred during implementation: {e}", 'error')

        elif action == 'decline_implementation':
            rule.status = 'Declined by Implementer'
            flash(f"Rule ID {rule.id} implementation declined.", 'warning')
            db.session.commit()
            app_logger.info(f"Implementer {current_user.username} (ID: {current_user.id}) declined implementation for rule {rule.id}.")

        return redirect(url_for('routes.implementation_list'))

    return render_template('implementation_detail.html', rule=rule)


@routes.route('/implementation')
@login_required
@roles_required('superadmin', 'admin', 'implementer')
def implementation_list():
    """
    Displays a list of network rule requests pending implementation.
    """
    rules = FirewallRule.query.filter(
        FirewallRule.status.in_(['Approved - Pending Implementation', 'Provisioning In Progress', 'Partially Implemented - Requires Attention'])
    ).order_by(FirewallRule.created_at.asc()).all()
    return render_template('implementation_list.html', rules=rules)


@routes.route('/cancel-request/<int:rule_id>', methods=['POST'])
@login_required
@roles_required('superadmin', 'admin', 'requester') # Only requester, superadmin, admin can cancel
def cancel_request(rule_id):
    """
    Allows a requester (or admin/superadmin) to cancel their own pending network requests.
    """
    rule = FirewallRule.query.get_or_404(rule_id)

    # A requester can only cancel their own rules that are not yet completed/denied/in progress.
    if current_user.has_role('requester') and rule.requester_id != current_user.id:
        app_logger.warning(f"Unauthorized cancellation attempt: User {current_user.username} (ID: {current_user.id}) tried to cancel rule {rule_id} owned by {rule.requester_id}.")
        return jsonify({"status": "error", "message": "You are not authorized to cancel this request."}), 403

    # Define statuses that CANNOT be cancelled via this method.
    if rule.status in ['Completed', 'Completed - No Provisioning Needed', 'Denied by Approver', 'Declined by Implementer', 'Partially Implemented - Requires Attention', 'Provisioning In Progress']:
        app_logger.warning(f"Cancellation attempt failed: Rule ID {rule_id} (status: {rule.status}) cannot be cancelled by {current_user.username}.")
        return jsonify({"status": "error", "message": f"This request is currently '{rule.status}' and cannot be cancelled."}), 400

    try:
        rule.status = "Cancelled by Requester"
        rule.approval_status = "Cancelled" # Update approval status as well
        # Optionally, add a comment indicating who cancelled it
        if rule.approver_comment:
            rule.approver_comment += f"\\nRequest cancelled by {current_user.username} at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}."
        else:
            rule.approver_comment = f"Request cancelled by {current_user.username} at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}."

        db.session.commit()
        app_logger.info(f"Network request ID {rule_id} cancelled by {current_user.username} (ID: {current_user.id}).")
        return jsonify({"status": "success", "message": f"Request ID {rule_id} has been successfully cancelled."}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Error cancelling request ID {rule_id} by {current_user.username}: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": f"An error occurred while cancelling the request: {e}"}), 500


@routes.route('/blacklist-rules')
@login_required
@roles_required('superadmin', 'admin')
def blacklist_rules_list():
    """
    Displays a list of all blacklist rules.
    Accessible only by superadmin and admin roles.
    """
    # NO DATABASE QUERY HERE - The JavaScript in the template will fetch rules via API
    app_logger.info("Rendering blacklist rules list page. Data will be loaded via JavaScript API call.")
    return render_template('blacklist_rules_list.html') # Remove rules=rules, error_message=str(e) from here


@routes.route('/api/blacklist_rules', methods=['GET'])
@login_required
@roles_required('superadmin', 'admin')
def api_get_blacklist_rules():
    """
    API endpoint to retrieve all blacklist rules as JSON.
    """
    app_logger.info("API: Attempting to retrieve all blacklist rules.")
    try:
        rules = BlacklistRule.query.order_by(BlacklistRule.sequence.asc()).all()
        # Convert list of model objects to list of dictionaries
        rules_data = [rule.to_dict() for rule in rules]
        app_logger.info(f"API: Successfully retrieved {len(rules_data)} blacklist rules.")
        return jsonify(rules_data), 200
    except Exception as e:
        app_logger.error(f"API: Error retrieving blacklist rules: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Failed to retrieve blacklist rules."}), 500


@routes.route('/blacklist-rules/add', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin', 'admin')
def add_blacklist_rule():
    """
    Allows superadmin and admin roles to add new blacklist rules.
    """
    if request.method == 'POST':
        sequence = request.form.get('sequence', type=int)
        rule_name = request.form.get('rule_name')
        enabled = request.form.get('enabled') == 'True'
        source_ip = request.form.get('source_ip') or None
        destination_ip = request.form.get('destination_ip') or None
        protocol = request.form.get('protocol') or None
        destination_port = request.form.get('destination_port') or None
        description = request.form.get('description') or None

        errors = []
        if not rule_name:
            errors.append("Rule Name is required.")
        if sequence is None:
            errors.append("Sequence is required and must be an integer.")
        elif BlacklistRule.query.filter_by(sequence=sequence).first():
            errors.append(f"A rule with sequence {sequence} already exists. Please choose a unique sequence number.")

        if source_ip:
            try:
                ipaddress.ip_network(source_ip, strict=False)
            except ValueError:
                errors.append("Invalid Source IP format.")

        if destination_ip:
            try:
                ipaddress.ip_network(destination_ip, strict=False)
            except ValueError:
                errors.append("Invalid Destination IP format.")

        if protocol and protocol.lower() not in ['tcp', 'udp', 'icmp', 'any', '6', '17', '1']:
            errors.append("Invalid Protocol. Must be tcp, udp, icmp, any, or protocol number.")

        if destination_port:
            if destination_port.lower() == 'any':
                pass
            else:
                try:
                    port_num = int(destination_port)
                    if not (0 <= port_num <= 65535):
                        errors.append("Invalid port number. Must be between 0-65535 or 'any'.")
                except ValueError:
                    errors.append("Invalid port format. Must be a single port number (0-65535) or 'any'.")

            if protocol and protocol.lower() in ['icmp', '1'] and destination_port and destination_port.lower() not in ['any', '']:
                errors.append("For ICMP protocol, destination port should be 'any' or left blank.")
            if protocol and protocol.lower() == 'any' and destination_port and destination_port.lower() not in ['any', '']:
                errors.append("For 'any' protocol, destination port should be 'any' or left blank.")

        if errors:
            for error in errors:
                flash(error, 'error')
            app_logger.warning(f"Validation errors for new blacklist rule from {current_user.username}: {errors}")
            return render_template('add_blacklist_form.html',
                                   sequence=sequence, rule_name=rule_name, enabled=enabled,
                                   source_ip=source_ip, destination_ip=destination_ip,
                                   protocol=protocol, destination_port=destination_port, description=description)

        new_rule = BlacklistRule(
            sequence=sequence,
            rule_name=rule_name,
            enabled=enabled,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            destination_port=destination_port,
            description=description
        )
        db.session.add(new_rule)
        try:
            db.session.commit()
            flash(f"Blacklist rule '{rule_name}' added successfully!", 'success')
            app_logger.info(f"Blacklist rule ID {new_rule.id} ('{new_rule.rule_name}') added by {current_user.username}.")
            return redirect(url_for('routes.blacklist_rules_list')) # Redirect to the list view
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding blacklist rule: {e}", 'error')
            app_logger.error(f"Error adding blacklist rule by {current_user.username}: {e}", exc_info=True)
            return render_template('add_blacklist_form.html',
                                   sequence=sequence, rule_name=rule_name, enabled=enabled,
                                   source_ip=source_ip, destination_ip=destination_ip,
                                   protocol=protocol, destination_port=destination_port, description=description)

    return render_template('add_blacklist_form.html')


@routes.route('/blacklist-rules/detail/<int:rule_id>')
@login_required
@roles_required('superadmin', 'admin')
def blacklist_rule_detail(rule_id):
    """
    Displays detailed information for a specific blacklist rule.
    """
    rule = BlacklistRule.query.get_or_404(rule_id)
    return render_template('blacklist_rule_detail.html', rule=rule)


@routes.route('/blacklist-rules/delete/<int:rule_id>', methods=['POST'])
@login_required
@roles_required('superadmin', 'admin')
def delete_blacklist_rule(rule_id):
    """
    Deletes a blacklist rule.
    """
    rule = BlacklistRule.query.get_or_404(rule_id)
    try:
        db.session.delete(rule)
        db.session.commit()
        flash(f"Blacklist rule '{rule.rule_name}' deleted successfully.", 'success')
        app_logger.info(f"Blacklist rule ID {rule_id} ('{rule.rule_name}') deleted by {current_user.username}.")
        return jsonify({"status": "success", "message": "Rule deleted."}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Error deleting blacklist rule {rule_id} by {current_user.username}: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": f"Error deleting rule: {e}"}), 500

# API endpoint for deleting multiple blacklist rules
@routes.route('/api/blacklist_rules', methods=['DELETE'])
@login_required
@roles_required('superadmin', 'admin')
def api_delete_blacklist_rules():
    """
    API endpoint to delete multiple blacklist rules by IDs.
    """
    data = request.get_json()
    rule_ids = data.get('ids', [])
    if not rule_ids:
        return jsonify({"status": "error", "message": "No rule IDs provided for deletion."}), 400

    try:
        deleted_count = 0
        for rule_id in rule_ids:
            rule = BlacklistRule.query.get(rule_id)
            if rule:
                db.session.delete(rule)
                deleted_count += 1
        db.session.commit()
        app_logger.info(f"API: {deleted_count} blacklist rules deleted by {current_user.username}: {rule_ids}.")
        return jsonify({"status": "success", "message": f"{deleted_count} rule(s) deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"API: Error deleting multiple blacklist rules by {current_user.username}: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"An error occurred during bulk deletion: {e}"}), 500


# API endpoint for deleting a single blacklist rule (used by individual delete buttons)
@routes.route('/api/blacklist_rules/<int:rule_id>', methods=['DELETE'])
@login_required
@roles_required('superadmin', 'admin')
def api_delete_single_blacklist_rule(rule_id):
    """
    API endpoint to delete a single blacklist rule by ID.
    """
    rule = BlacklistRule.query.get(rule_id)
    if not rule:
        return jsonify({"status": "error", "message": f"Rule with ID {rule_id} not found."}), 404

    try:
        db.session.delete(rule)
        db.session.commit()
        app_logger.info(f"API: Blacklist rule ID {rule_id} deleted by {current_user.username}.")
        return jsonify({"status": "success", "message": f"Rule ID {rule_id} deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"API: Error deleting single blacklist rule {rule_id} by {current_user.username}: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"An error occurred during deletion: {e}"}), 500


@routes.route('/admin/edit-blacklist-rule/<int:rule_id>', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin', 'admin') # Ensure only authorized users can edit
def edit_blacklist_rule(rule_id):
    """
    Allows superadmin and admin roles to edit existing blacklist rules.
    """
    rule = BlacklistRule.query.get_or_404(rule_id)

    if request.method == 'POST':
        sequence = request.form.get('sequence', type=int)
        rule_name = request.form.get('rule_name')
        enabled = request.form.get('enabled') == 'True'
        source_ip = request.form.get('source_ip') or None
        destination_ip = request.form.get('destination_ip') or None
        protocol = request.form.get('protocol') or None
        destination_port = request.form.get('destination_port') or None
        description = request.form.get('description') or None

        errors = []
        if not rule_name:
            errors.append("Rule Name is required.")
        if sequence is None:
            errors.append("Sequence is required and must be an integer.")
        # Check for sequence uniqueness only if it's being changed and conflicts with another rule
        elif sequence != rule.sequence and BlacklistRule.query.filter_by(sequence=sequence).first():
            errors.append(f"A rule with sequence {sequence} already exists. Please choose a unique sequence number.")

        if source_ip:
            try:
                ipaddress.ip_network(source_ip, strict=False)
            except ValueError:
                errors.append("Invalid Source IP format.")

        if destination_ip:
            try:
                ipaddress.ip_network(destination_ip, strict=False)
            except ValueError:
                errors.append("Invalid Destination IP format.")

        if protocol and protocol.lower() not in ['tcp', 'udp', 'icmp', 'any', '6', '17', '1']:
            errors.append("Invalid Protocol. Must be tcp, udp, icmp, any, or protocol number.")

        if destination_port:
            if destination_port.lower() == 'any':
                pass
            else:
                try:
                    port_num = int(destination_port)
                    if not (0 <= port_num <= 65535):
                        errors.append("Invalid port number. Must be between 0-65535 or 'any'.")
                except ValueError:
                    errors.append("Invalid port format. Must be a single port number (0-65535) or 'any'.")

            if protocol and protocol.lower() in ['icmp', '1'] and destination_port and destination_port.lower() not in ['any', '']:
                errors.append("For ICMP protocol, destination port should be 'any' or left blank.")
            if protocol and protocol.lower() == 'any' and destination_port and destination_port.lower() not in ['any', '']:
                errors.append("For 'any' protocol, destination port should be 'any' or left blank.")

        if errors:
            for error in errors:
                flash(error, 'error')
            app_logger.warning(f"Validation errors for editing blacklist rule {rule.id} from {current_user.username}: {errors}")
            return render_template('add_blacklist_form.html',
                                   sequence=sequence, rule_name=rule_name, enabled=enabled,
                                   source_ip=source_ip, destination_ip=destination_ip,
                                   protocol=protocol, destination_port=destination_port, description=description,
                                   title=f'Edit Blacklist Rule ID: {rule_id}')

        rule.sequence = sequence
        rule.rule_name = rule_name
        rule.enabled = enabled
        rule.source_ip = source_ip
        rule.destination_ip = destination_ip
        rule.protocol = protocol
        rule.destination_port = destination_port
        rule.description = description

        try:
            db.session.commit()
            flash(f'Blacklist rule {rule.id} updated successfully!', 'success')
            app_logger.info(f"Blacklist rule {rule.id} updated by {current_user.username}.")
            return redirect(url_for('routes.blacklist_rules_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating blacklist rule: {e}', 'error')
            app_logger.error(f"Error updating blacklist rule {rule.id} by {current_user.username}: {e}", exc_info=True)
            return render_template('add_blacklist_form.html',
                                   sequence=sequence, rule_name=rule_name, enabled=enabled,
                                   source_ip=source_ip, destination_ip=destination_ip,
                                   protocol=protocol, destination_port=destination_port, description=description,
                                   title=f'Edit Blacklist Rule ID: {rule_id}')

    # For GET requests (initial load of the edit page)
    # Populate the form with the existing rule's data
    return render_template('add_blacklist_form.html',
                           sequence=rule.sequence,
                           rule_name=rule.rule_name,
                           enabled=rule.enabled,
                           source_ip=rule.source_ip,
                           destination_ip=rule.destination_ip,
                           protocol=rule.protocol,
                           destination_port=rule.destination_port,
                           description=rule.description,
                           title=f'Edit Blacklist Rule ID: {rule_id}')

@routes.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """
    Allows a user to view and update their profile information (email, first/last name, password).
    Username and role are not editable by the user.
    """
    user = current_user # The Flask-Login current_user object

    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        password = request.form.get('password') # New password, if provided

        errors = []

        # Validate email
        if not email:
            errors.append('Email is required.')
        elif email != user.email and User.query.filter_by(email=email).first():
            errors.append('Email address already registered by another user.')

        if errors:
            for error in errors:
                flash(error, 'error')
            app_logger.warning(f"Profile update failed for {user.username}: {errors}")
            # Re-render the form with current data and errors
            return render_template('profile.html', user=user)

        user.email = email
        user.first_name = first_name
        user.last_name = last_name

        if password: # Only update password if a new one is provided
            user.set_password(password)
            flash('Password updated successfully.', 'success')
            app_logger.info(f"User {user.username} (ID: {user.id}) updated their password.")

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            app_logger.info(f"User {user.username} (ID: {user.id}) updated their profile.")
            return redirect(url_for('routes.profile'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating profile: {e}", 'error')
            app_logger.error(f"Error updating profile for {user.username}: {e}", exc_info=True)
            return render_template('profile.html', user=user)

    return render_template('profile.html', user=user)
