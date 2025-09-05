# <img width="30" height="30" alt="favicon" src="https://github.com/user-attachments/assets/7c2c2f10-88b4-481d-8f05-fa4dd45754eb" /> Firework – Policy Rule Authentication and Certification for Secure Firewall Management  

## Overview  
**Firework** is a prototype web application developed as part of an MSc Cybersecurity thesis. It was created to address the **security, compliance, and auditability gaps** in traditional firewall policy management.  

Enterprise firewall changes are often done manually, which can lead to:  
- Misconfigurations that introduce vulnerabilities.  
- Lack of consistent approval and accountability.  
- Difficulty proving compliance during audits.  

Firework introduces a **secure, automated, and auditable workflow** for managing firewall rules in **multi-vendor environments** (FortiGate & Palo Alto). It combines:  
- **Role-Based Access Control (RBAC)** to enforce separation of duties.  
- **Approval workflows** to prevent self-approval.  
- **Pre-checks & post-checks** for rule validation and certification.  
- **Comprehensive logging** for accountability and audit readiness.  

The app demonstrates how **open-source automation (Flask + Ansible + PostgreSQL)** can be adapted to create a **trusted firewall management system** for both operations teams and compliance officers.  

<img width="600" height="400" alt="Firework-Architecture" src="https://github.com/user-attachments/assets/5f79685f-ede6-4319-bf2c-178c866d6e13" />


---

## Features  
- **RBAC User Management** (SuperAdmin, Admin, Approver, Requester).  
- **Workflow**: Request → Pre-check → Approval → Provision → Post-check.  
- **Pre-checks**:
  - Blacklist validation.  
  - Network path analysis (reachability check).  
  - Conflicting rule detection.  
- **Automated rule provisioning** via Ansible (FortiGate & Palo Alto).  
- **Post-deployment certification** to confirm success.  
- **Dashboard + Audit Logs** for monitoring and compliance.  

---

## Simplifications & Assumptions  
- IPv4 only.  
- Only **permit** rules supported (no deny rules).  
- Source/destination limited to **0.0.0.0 or /32 host addresses**.  
- Single destination port (1–65535).  
- Destination must exist in device routing tables (no reliance on default routes).  
- Device type inferred by **hostname convention**, not Ansible facts.
  - R = Router
  - SW = Switch
  - pafw = Firewal
  - fgt = Firewall
- Devices assumed preconfigured with admin users, interfaces, VLANs, OSPF, etc.  

---

## Quickstart  

### Requirements  
- Ubuntu 24.04+
- Internet access
- **firework** user as sudoer

### Installation
The install.sh script will:
- Update/upgrade the OS.
- Install, configure, and verify (if not already installed):
  - Python
  - Nginx
  - PostgreSQL
  - Ansible
- Create necessary users, folders, files, and set correct ownership and permissions.
- Create and enable the firework.service systemd unit.
- Prompt you for:
  - SECRET_KEY
  - PostgreSQL password
  - Ansible Vault password
  - Ansible Vault inventory variables
  - Template inventory.yml file

```bash
git clone https://github.com/pynetscript/firework.git
cd firework/scripts
sudo chmod +x install.sh && ./install.sh
```

Access at [http://<ipv4_address]

Login credentials:
- `super_admin / super_admin`

<img width="1920" height="1032" alt="image" src="https://github.com/user-attachments/assets/adc9e3ba-7d86-4c75-a2b9-f9aaeded9159" />

---

## Reset the Environment  
If you need to reset the app and database completely:

```bash
./scripts/reset.sh
```

---
